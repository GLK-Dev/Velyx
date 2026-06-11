use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use velyx::{
    CAP_OBFS_V1, CAP_RELAY_V1, CapabilitySet, ClientFinish, ClientHello, ControlAck,
    ControlAssembler, ControlChunk, HEADER_LEN, Negotiated, PROTOCOL_VERSION, PacketType,
    ReplayWindow, ServerHello, VWP_STREAM_ID_LEN, VwpFrame, VwpFrameType, WirePacket,
    chunk_control_message, negotiate, parse_server_and_validate,
};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

struct PeerSession {
    session_id: u64,
    negotiated: Negotiated,
    recv_replay: ReplayWindow,
    tx_seq: u64,
    vwp_tx_seq: u32,
    handshake: Option<HandshakeState>,
    transport: Option<TransportState>,
    control_assembler: ControlAssembler,
}

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

    let static_key = noise_private_key()?;
    let local = local_caps();
    let mut peers: HashMap<SocketAddr, PeerSession> = HashMap::new();
    let mut in_buf = [0u8; 4096];
    let mut out_buf = [0u8; 4096];

    loop {
        let (len, remote) = socket
            .recv_from(&mut in_buf)
            .await
            .context("failed to receive UDP datagram")?;

        let packet = match WirePacket::decode(&in_buf[..len]) {
            Ok(packet) => packet,
            Err(err) => {
                println!("Dropping invalid packet from {remote}: {err}");
                continue;
            }
        };

        if packet.version != PROTOCOL_VERSION {
            println!(
                "Dropping packet from {remote}: unsupported version {}",
                packet.version
            );
            continue;
        }

        if let Some(session) = peers.get_mut(&remote) {
            if packet.session_id != session.session_id {
                println!(
                    "Dropping packet from {remote}: session mismatch got {}, expected {}",
                    packet.session_id, session.session_id
                );
                continue;
            }

            if let Err(err) = session.recv_replay.check_and_record(packet.seq) {
                println!("Dropping replay/out-of-window packet from {remote}: {err}");
                continue;
            }

            if let Some(hs) = session.handshake.as_mut() {
                if packet.packet_type != PacketType::Handshake3 {
                    println!(
                        "Dropping unexpected packet from {remote} during handshake: {:?}",
                        packet.packet_type
                    );
                    continue;
                }

                let finish_len = match hs.read_message(&packet.payload, &mut out_buf) {
                    Ok(len) => len,
                    Err(err) => {
                        println!("Failed handshake message 3 from {remote}: {err}");
                        peers.remove(&remote);
                        continue;
                    }
                };

                let finish = match ClientFinish::decode(&out_buf[..finish_len]) {
                    Ok(finish) => finish,
                    Err(err) => {
                        println!("Invalid client finish payload from {remote}: {err}");
                        peers.remove(&remote);
                        continue;
                    }
                };

                if let Err(err) = validate_finish(finish, session.negotiated) {
                    println!("Negotiation validation failed for {remote}: {err}");
                    peers.remove(&remote);
                    continue;
                }

                let hs_owned = match session.handshake.take() {
                    Some(state) => state,
                    None => {
                        println!("Internal state error: missing handshake for {remote}");
                        peers.remove(&remote);
                        continue;
                    }
                };

                let transport = match hs_owned.into_transport_mode() {
                    Ok(mode) => mode,
                    Err(err) => {
                        println!("Failed to switch to transport mode for {remote}: {err}");
                        peers.remove(&remote);
                        continue;
                    }
                };
                session.transport = Some(transport);

                println!("Secure channel established with {remote}");
                println!(
                    "Negotiated version={} caps=0x{:016x}",
                    session.negotiated.version, session.negotiated.caps
                );
                continue;
            }

            let Some(transport) = session.transport.as_mut() else {
                println!("Internal state error: no handshake/transport for {remote}");
                peers.remove(&remote);
                continue;
            };

            if packet.packet_type != PacketType::Data {
                println!(
                    "Dropping unexpected secure packet from {remote}: {:?}",
                    packet.packet_type
                );
                continue;
            }

            let msg_len = match transport.read_message(&packet.payload, &mut out_buf) {
                Ok(len) => len,
                Err(err) => {
                    println!("Failed to decrypt payload from {remote}: {err}");
                    continue;
                }
            };
            let vwp = match VwpFrame::decode(&out_buf[..msg_len]) {
                Ok(frame) => frame,
                Err(err) => {
                    println!("Failed to decode VWP frame from {remote}: {err}");
                    continue;
                }
            };

            match vwp.frame_type {
                VwpFrameType::Control => {
                    let chunk = match ControlChunk::decode(&vwp.payload) {
                        Ok(chunk) => chunk,
                        Err(err) => {
                            println!("Invalid control chunk from {remote}: {err}");
                            continue;
                        }
                    };

                    // ACK each control chunk for reliable metadata delivery.
                    let ack = ControlAck {
                        message_id: chunk.message_id,
                        chunk_index: chunk.chunk_index,
                    };
                    let ack_frame = VwpFrame {
                        frame_type: VwpFrameType::Ack,
                        seq: session.vwp_tx_seq,
                        stream_id: vwp.stream_id,
                        payload: ack.encode().to_vec(),
                    };
                    session.vwp_tx_seq = session.vwp_tx_seq.wrapping_add(1);

                    let ack_wire_len = match ack_frame.encode() {
                        Ok(bytes) => match transport.write_message(&bytes, &mut out_buf) {
                            Ok(n) => n,
                            Err(err) => {
                                println!("Failed to encrypt control ACK for {remote}: {err}");
                                continue;
                            }
                        },
                        Err(err) => {
                            println!("Failed to encode control ACK for {remote}: {err}");
                            continue;
                        }
                    };
                    let ack_packet = WirePacket {
                        version: PROTOCOL_VERSION,
                        packet_type: PacketType::Data,
                        flags: 0,
                        session_id: session.session_id,
                        seq: session.tx_seq,
                        payload: out_buf[..ack_wire_len].to_vec(),
                    };
                    session.tx_seq += 1;
                    let ack_raw = match ack_packet.encode() {
                        Ok(raw) => raw,
                        Err(err) => {
                            println!("Failed to encode ACK packet for {remote}: {err}");
                            continue;
                        }
                    };
                    if let Err(err) = socket.send_to(&ack_raw, remote).await {
                        println!("Failed to send ACK packet to {remote}: {err}");
                        continue;
                    }

                    let assembled = match session.control_assembler.push_chunk(chunk) {
                        Ok(result) => result,
                        Err(err) => {
                            println!("Control assembler error for {remote}: {err}");
                            continue;
                        }
                    };

                    if let Some(full) = assembled {
                        let as_text = String::from_utf8_lossy(&full);
                        println!("[{remote}] Assembled control payload ({} bytes)", full.len());
                        println!("[{remote}] Control text: {as_text}");

                        let data_frame = VwpFrame {
                            frame_type: VwpFrameType::Data,
                            seq: session.vwp_tx_seq,
                            stream_id: vwp.stream_id,
                            payload: b"velyx-pong".to_vec(),
                        };
                        session.vwp_tx_seq = session.vwp_tx_seq.wrapping_add(1);

                        let data_wire_len = match data_frame.encode() {
                            Ok(bytes) => match transport.write_message(&bytes, &mut out_buf) {
                                Ok(n) => n,
                                Err(err) => {
                                    println!("Failed to encrypt data reply for {remote}: {err}");
                                    continue;
                                }
                            },
                            Err(err) => {
                                println!("Failed to encode VWP data reply for {remote}: {err}");
                                continue;
                            }
                        };

                        let reply_packet = WirePacket {
                            version: PROTOCOL_VERSION,
                            packet_type: PacketType::Data,
                            flags: 0,
                            session_id: session.session_id,
                            seq: session.tx_seq,
                            payload: out_buf[..data_wire_len].to_vec(),
                        };
                        session.tx_seq += 1;
                        let reply_raw = match reply_packet.encode() {
                            Ok(raw) => raw,
                            Err(err) => {
                                println!("Failed to encode data reply packet for {remote}: {err}");
                                continue;
                            }
                        };
                        if let Err(err) = socket.send_to(&reply_raw, remote).await {
                            println!("Failed to send data reply to {remote}: {err}");
                        }
                    }
                }
                VwpFrameType::Ack => {
                    println!("[{remote}] Received ACK frame on responder side");
                }
                VwpFrameType::Data => {
                    let incoming = String::from_utf8_lossy(&vwp.payload);
                    println!("[{remote}] Data frame payload: {incoming}");
                }
            }
            continue;
        }

        if packet.packet_type != PacketType::Handshake1 {
            println!(
                "Dropping packet from unknown peer {remote}: expected Handshake1, got {:?}",
                packet.packet_type
            );
            continue;
        }

        let params: NoiseParams = match NOISE_PATTERN.parse() {
            Ok(params) => params,
            Err(err) => {
                println!("Failed to parse noise pattern for new peer {remote}: {err}");
                continue;
            }
        };

        let mut hs = match Builder::new(params)
            .local_private_key(&static_key)
            .build_responder()
        {
            Ok(state) => state,
            Err(err) => {
                println!("Failed to build responder state for {remote}: {err}");
                continue;
            }
        };

        let mut recv_replay = ReplayWindow::default();
        if let Err(err) = recv_replay.check_and_record(packet.seq) {
            println!("Invalid initial sequence from {remote}: {err}");
            continue;
        }

        let hello_len = match hs.read_message(&packet.payload, &mut out_buf) {
            Ok(len) => len,
            Err(err) => {
                println!("Failed handshake message 1 from {remote}: {err}");
                continue;
            }
        };
        let remote_hello = match ClientHello::decode(&out_buf[..hello_len]) {
            Ok(hello) => hello,
            Err(err) => {
                println!("Invalid client hello in message 1 from {remote}: {err}");
                continue;
            }
        };
        let selected = match negotiate(local, remote_hello) {
            Ok(negotiated) => negotiated,
            Err(err) => {
                println!("Negotiation failed for {remote}: {err}");
                continue;
            }
        };

        let hello2 = ServerHello {
            min_version: local.min_version,
            max_version: local.max_version,
            caps: local.mask,
            selected_version: selected.version,
            selected_caps: selected.caps,
        };

        let len2 = match hs.write_message(&hello2.encode(), &mut out_buf) {
            Ok(len) => len,
            Err(err) => {
                println!("Failed to write handshake message 2 for {remote}: {err}");
                continue;
            }
        };
        let hs2_packet = WirePacket {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Handshake2,
            flags: 0,
            session_id: packet.session_id,
            seq: 0,
            payload: out_buf[..len2].to_vec(),
        };
        let hs2_raw = match hs2_packet.encode() {
            Ok(raw) => raw,
            Err(err) => {
                println!("Failed to encode handshake message 2 for {remote}: {err}");
                continue;
            }
        };
        if let Err(err) = socket.send_to(&hs2_raw, remote).await {
            println!("Failed to send handshake message 2 to {remote}: {err}");
            continue;
        }

        peers.insert(
            remote,
            PeerSession {
                session_id: packet.session_id,
                negotiated: selected,
                recv_replay,
                tx_seq: 1,
                vwp_tx_seq: 0,
                handshake: Some(hs),
                transport: None,
                control_assembler: ControlAssembler::default(),
            },
        );

        println!("Handshake msg1 received from {remote}");
        println!("Active peer sessions: {}", peers.len());
    }
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

    let mut stream_id = [0u8; VWP_STREAM_ID_LEN];
    stream_id[0..8].copy_from_slice(&session_id.to_be_bytes());

    let control_payload = b"control: metadata handshake for swarm bootstrap over reliable chunks";
    let control_frames = chunk_control_message(stream_id, 1, 0, control_payload)
        .context("failed to chunk control payload")?;
    let expected_acks = control_frames.len();

    for control_frame in &control_frames {
        let vwp_raw = control_frame.encode().context("encode VWP control frame")?;
        let enc_len = transport
            .write_message(&vwp_raw, &mut out_buf)
            .context("failed to encrypt VWP control frame")?;
        let data_pkt = WirePacket {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Data,
            flags: 0,
            session_id,
            seq: tx_seq,
            payload: out_buf[..enc_len].to_vec(),
        };
        tx_seq += 1;
        let data_raw = data_pkt.encode()?;
        socket
            .send_to(&data_raw, remote)
            .await
            .context("failed to send control chunk")?;
    }

    let mut acked_chunks = 0usize;
    loop {
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
        let frame = VwpFrame::decode(&out_buf[..plain_len]).context("decode VWP response")?;

        match frame.frame_type {
            VwpFrameType::Ack => {
                let ack = ControlAck::decode(&frame.payload).context("decode control ACK")?;
                println!(
                    "Received control ACK: message_id={}, chunk_index={}",
                    ack.message_id, ack.chunk_index
                );
                acked_chunks += 1;
                if acked_chunks == expected_acks {
                    println!("All control chunks acknowledged ({acked_chunks}/{expected_acks})");
                }
            }
            VwpFrameType::Data => {
                let response = String::from_utf8_lossy(&frame.payload);
                println!("Received VWP data response: {response}");
                if acked_chunks >= expected_acks {
                    break;
                }
            }
            VwpFrameType::Control => {
                println!("Received unexpected control frame from responder");
            }
        }
    }

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
