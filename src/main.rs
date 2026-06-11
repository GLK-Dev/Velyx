use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use snow::{Builder, params::NoiseParams};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use velyx::{
    CAP_OBFS_V1, CAP_RELAY_V1, CapabilitySet, ClientFinish, ClientHello, HEADER_LEN, Negotiated,
    PROTOCOL_VERSION, PacketType, ReplayWindow, ServerHello, WirePacket, negotiate,
    parse_server_and_validate,
};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        print_usage();
        bail!("not enough arguments");
    }

    let mode = args[1].as_str();
    let bind_addr = args[2].as_str();

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let peer_id = hex::encode(signing_key.verifying_key().as_bytes());
    println!("Velyx node started");
    println!("Peer ID (ed25519): {peer_id}");

    match mode {
        "responder" => run_responder(bind_addr).await,
        "initiator" => {
            if args.len() < 4 {
                print_usage();
                bail!("initiator mode needs a remote address");
            }
            run_initiator(bind_addr, args[3].as_str()).await
        }
        _ => {
            print_usage();
            bail!("unknown mode: {mode}")
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  velyx responder <bind_addr>");
    println!("  velyx initiator <bind_addr> <remote_addr>");
    println!("Examples:");
    println!("  velyx responder 0.0.0.0:9000");
    println!("  velyx initiator 0.0.0.0:0 127.0.0.1:9000");
}

fn local_caps() -> CapabilitySet {
    let mut caps = CapabilitySet::mvp_default();
    caps.mask |= CAP_RELAY_V1;
    caps.mask |= CAP_OBFS_V1;
    caps
}

fn noise_private_key() -> Result<Vec<u8>> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .context("failed to parse noise pattern")?;
    let keypair = Builder::new(params)
        .generate_keypair()
        .context("failed to generate noise static keypair")?;
    Ok(keypair.private)
}

async fn run_responder(bind_addr: &str) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind responder socket on {bind_addr}"))?;
    println!("Responder listening on {bind_addr}");

    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .context("failed to parse noise pattern")?;
    let static_key = noise_private_key()?;

    let mut hs = Builder::new(params)
        .local_private_key(&static_key)
        .build_responder()
        .context("failed to build responder state")?;

    let mut in_buf = [0u8; 4096];
    let mut out_buf = [0u8; 4096];
    let mut recv_replay = ReplayWindow::default();
    let mut tx_seq = 0u64;

    let local = local_caps();

    let (len1, remote) = socket
        .recv_from(&mut in_buf)
        .await
        .context("failed to receive handshake message 1")?;
    let pkt1 = decode_and_validate(
        &in_buf[..len1],
        PacketType::Handshake1,
        PROTOCOL_VERSION,
        None,
        &mut recv_replay,
    )?;
    let hello_len = hs
        .read_message(&pkt1.payload, &mut out_buf)
        .context("failed to parse handshake message 1")?;
    let remote_hello = ClientHello::decode(&out_buf[..hello_len])
        .context("invalid client hello in handshake message 1")?;
    let selected = negotiate(local, remote_hello)?;

    println!("Handshake msg1 received from {remote}");

    let hello2 = ServerHello {
        min_version: local.min_version,
        max_version: local.max_version,
        caps: local.mask,
        selected_version: selected.version,
        selected_caps: selected.caps,
    };

    let len2 = hs
        .write_message(&hello2.encode(), &mut out_buf)
        .context("failed to write handshake message 2")?;
    let wire2 = WirePacket {
        version: PROTOCOL_VERSION,
        packet_type: PacketType::Handshake2,
        flags: 0,
        session_id: pkt1.session_id,
        seq: tx_seq,
        payload: out_buf[..len2].to_vec(),
    };
    tx_seq += 1;
    let raw2 = wire2.encode()?;
    socket
        .send_to(&raw2, remote)
        .await
        .context("failed to send handshake message 2")?;

    let (len3, remote2) = socket
        .recv_from(&mut in_buf)
        .await
        .context("failed to receive handshake message 3")?;
    if remote2 != remote {
        bail!("handshake source mismatch: expected {remote}, got {remote2}");
    }
    let pkt3 = decode_and_validate(
        &in_buf[..len3],
        PacketType::Handshake3,
        PROTOCOL_VERSION,
        Some(pkt1.session_id),
        &mut recv_replay,
    )?;
    let finish_len = hs
        .read_message(&pkt3.payload, &mut out_buf)
        .context("failed to parse handshake message 3")?;
    let finish = ClientFinish::decode(&out_buf[..finish_len])
        .context("invalid client finish payload")?;
    validate_finish(finish, selected)?;
    println!("Secure channel established with {remote}");
    println!(
        "Negotiated version={} caps=0x{:016x}",
        selected.version, selected.caps
    );

    let mut transport = hs
        .into_transport_mode()
        .context("failed to switch to transport mode")?;

    let (enc_len, remote3) = socket
        .recv_from(&mut in_buf)
        .await
        .context("failed to receive encrypted payload")?;
    if remote3 != remote {
        bail!("payload source mismatch: expected {remote}, got {remote3}");
    }

    let data_packet = decode_and_validate(
        &in_buf[..enc_len],
        PacketType::Data,
        PROTOCOL_VERSION,
        Some(pkt1.session_id),
        &mut recv_replay,
    )?;

    let msg_len = transport
        .read_message(&data_packet.payload, &mut out_buf)
        .context("failed to decrypt payload")?;
    let incoming = String::from_utf8_lossy(&out_buf[..msg_len]);
    println!("Decrypted payload: {incoming}");

    let reply = b"velyx-pong";
    let enc_reply_len = transport
        .write_message(reply, &mut out_buf)
        .context("failed to encrypt response")?;
    let reply_packet = WirePacket {
        version: PROTOCOL_VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        session_id: pkt1.session_id,
        seq: tx_seq,
        payload: out_buf[..enc_reply_len].to_vec(),
    };
    let reply_raw = reply_packet.encode()?;
    socket
        .send_to(&reply_raw, remote)
        .await
        .context("failed to send encrypted response")?;

    println!("Encrypted response sent");
    Ok(())
}

async fn run_initiator(bind_addr: &str, remote_addr: &str) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind initiator socket on {bind_addr}"))?;
    let remote: SocketAddr = remote_addr
        .parse()
        .with_context(|| format!("invalid remote address: {remote_addr}"))?;
    println!("Initiator bound on {bind_addr}, remote: {remote}");

    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .context("failed to parse noise pattern")?;
    let static_key = noise_private_key()?;

    let mut hs = Builder::new(params)
        .local_private_key(&static_key)
        .build_initiator()
        .context("failed to build initiator state")?;

    let mut in_buf = [0u8; 4096];
    let mut out_buf = [0u8; 4096];
    let mut recv_replay = ReplayWindow::default();
    let mut tx_seq = 0u64;
    let local = local_caps();
    let mut session_id_rng = OsRng;
    let session_id = session_id_rng.next_u64();

    let hello1 = ClientHello {
        min_version: local.min_version,
        max_version: local.max_version,
        caps: local.mask,
    };

    let len1 = hs
        .write_message(&hello1.encode(), &mut out_buf)
        .context("failed to write handshake message 1")?;
    let pkt1 = WirePacket {
        version: PROTOCOL_VERSION,
        packet_type: PacketType::Handshake1,
        flags: 0,
        session_id,
        seq: tx_seq,
        payload: out_buf[..len1].to_vec(),
    };
    tx_seq += 1;
    let raw1 = pkt1.encode()?;
    socket
        .send_to(&raw1, remote)
        .await
        .context("failed to send handshake message 1")?;

    let (len2, from2) = socket
        .recv_from(&mut in_buf)
        .await
        .context("failed to receive handshake message 2")?;
    if from2 != remote {
        bail!("handshake source mismatch: expected {remote}, got {from2}");
    }
    let pkt2 = decode_and_validate(
        &in_buf[..len2],
        PacketType::Handshake2,
        PROTOCOL_VERSION,
        Some(session_id),
        &mut recv_replay,
    )?;
    let server_hello_len = hs
        .read_message(&pkt2.payload, &mut out_buf)
        .context("failed to parse handshake message 2")?;
    let server_hello = ServerHello::decode(&out_buf[..server_hello_len])
        .context("invalid server hello payload")?;
    let selected = parse_server_and_validate(local, server_hello)?;

    let finish = ClientFinish {
        selected_version: selected.version,
        selected_caps: selected.caps,
    };

    let len3 = hs
        .write_message(&finish.encode(), &mut out_buf)
        .context("failed to write handshake message 3")?;
    let pkt3 = WirePacket {
        version: PROTOCOL_VERSION,
        packet_type: PacketType::Handshake3,
        flags: 0,
        session_id,
        seq: tx_seq,
        payload: out_buf[..len3].to_vec(),
    };
    tx_seq += 1;
    let raw3 = pkt3.encode()?;
    socket
        .send_to(&raw3, remote)
        .await
        .context("failed to send handshake message 3")?;
    println!("Secure channel established with {remote}");
    println!(
        "Negotiated version={} caps=0x{:016x}",
        selected.version, selected.caps
    );

    let mut transport = hs
        .into_transport_mode()
        .context("failed to switch to transport mode")?;

    let payload = b"velyx-ping";
    let enc_len = transport
        .write_message(payload, &mut out_buf)
        .context("failed to encrypt payload")?;
    let data_pkt = WirePacket {
        version: PROTOCOL_VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        session_id,
        seq: tx_seq,
        payload: out_buf[..enc_len].to_vec(),
    };
    let data_raw = data_pkt.encode()?;
    socket
        .send_to(&data_raw, remote)
        .await
        .context("failed to send encrypted payload")?;

    let (resp_len, from3) = socket
        .recv_from(&mut in_buf)
        .await
        .context("failed to receive encrypted response")?;
    if from3 != remote {
        bail!("response source mismatch: expected {remote}, got {from3}");
    }
    let response_pkt = decode_and_validate(
        &in_buf[..resp_len],
        PacketType::Data,
        PROTOCOL_VERSION,
        Some(session_id),
        &mut recv_replay,
    )?;
    let plain_len = transport
        .read_message(&response_pkt.payload, &mut out_buf)
        .context("failed to decrypt response")?;
    let response = String::from_utf8_lossy(&out_buf[..plain_len]);
    println!("Decrypted response: {response}");

    Ok(())
}

fn decode_and_validate(
    raw: &[u8],
    expected_type: PacketType,
    expected_version: u8,
    expected_session: Option<u64>,
    replay: &mut ReplayWindow,
) -> Result<WirePacket> {
    if raw.len() < HEADER_LEN {
        bail!("packet shorter than header");
    }

    let packet = WirePacket::decode(raw)?;
    if packet.version != expected_version {
        bail!(
            "unsupported packet version: got {}, expected {}",
            packet.version,
            expected_version
        );
    }
    if packet.packet_type != expected_type {
        bail!(
            "unexpected packet type: got {:?}, expected {:?}",
            packet.packet_type,
            expected_type
        );
    }
    if let Some(sid) = expected_session {
        if packet.session_id != sid {
            bail!(
                "session mismatch: got {}, expected {}",
                packet.session_id,
                sid
            );
        }
    }
    replay.check_and_record(packet.seq)?;
    Ok(packet)
}

fn validate_finish(finish: ClientFinish, selected: Negotiated) -> Result<()> {
    if finish.selected_version != selected.version {
        bail!(
            "client finish version mismatch: got {}, expected {}",
            finish.selected_version,
            selected.version
        );
    }
    if finish.selected_caps != selected.caps {
        bail!(
            "client finish capabilities mismatch: got {:#x}, expected {:#x}",
            finish.selected_caps,
            selected.caps
        );
    }
    Ok(())
}
