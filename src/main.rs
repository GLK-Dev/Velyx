use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use velyx::{
    CAP_OBFS_V1, CAP_RELAY_V1, CapabilitySet, ClientFinish, ClientHello, ControlAck,
    ControlAssembler, ControlChunk, HEADER_LEN, Negotiated, PROTOCOL_VERSION, PacketType,
    ReplayWindow, ServerHello, VWP_STREAM_ID_LEN, VwpFrame, VwpFrameType, WirePacket,
    chunk_control_message, negotiate, parse_server_and_validate,
};
use velyx::stream::{
    ChaosConfig, DirtyNetwork, StreamCommand, StreamControlEvent, StreamReceiver, StreamSender,
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
    stream_receiver: StreamReceiver,
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
        "responder" => {
            let chaos = parse_chaos_config(&args)?;
            let chaos_middleware = match chaos {
                Some(cfg) => Some(DirtyNetwork::new(cfg, 0xC0FFEE)?),
                None => None,
            };
            run_responder(bind_addr, chaos_middleware).await
        }
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
    println!("  velyx responder <bind_addr> [--chaos-drop-data-pct <0-100>]");
    println!("  velyx initiator <bind_addr> <remote_addr>");
    println!("Examples:");
    println!("  velyx responder 0.0.0.0:9000");
    println!("  velyx responder 0.0.0.0:9000 --chaos-drop-data-pct 30");
    println!("  velyx initiator 0.0.0.0:0 127.0.0.1:9000");
}

fn parse_chaos_config(args: &[String]) -> Result<Option<ChaosConfig>> {
    if args.len() == 3 {
        return Ok(None);
    }
    if args.len() != 5 || args[3] != "--chaos-drop-data-pct" {
        print_usage();
        bail!("invalid responder options");
    }

    let drop_data_pct: u8 = args[4]
        .parse()
        .with_context(|| format!("invalid chaos drop percentage: {}", args[4]))?;

    Ok(Some(ChaosConfig {
        drop_data_pct,
        drop_control_pct: 0,
        drop_ack_pct: 0,
    }))
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

async fn run_responder(bind_addr: &str, mut chaos: Option<DirtyNetwork>) -> Result<()> {
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
                        println!("[{remote}] Assembled control payload ({} bytes)", full.len());
                        if full.is_empty() {
                            println!("[{remote}] Empty control payload");
                            continue;
                        }

                        match session.stream_receiver.on_control_payload(&full) {
                            Ok(StreamControlEvent::Started) => {
                                if let Ok(StreamCommand::StreamStart(cfg)) = StreamCommand::decode(&full) {
                                    println!(
                                        "[{remote}] Stream started: symbol_size={}, transfer_length={}",
                                        cfg.symbol_size(),
                                        cfg.transfer_length()
                                    );
                                }
                            }
                            Ok(StreamControlEvent::Stopped) => {
                                println!("[{remote}] Stream stopped by remote request");
                            }
                            Ok(StreamControlEvent::Ignored) => {
                                let as_text = String::from_utf8_lossy(&full);
                                println!("[{remote}] Control payload ignored: {as_text}");
                            }
                            Err(err) => {
                                println!("[{remote}] Invalid stream control payload: {err}");
                            }
                        }
                    }
                }
                VwpFrameType::Ack => {
                    println!("[{remote}] Received ACK frame on responder side");
                }
                VwpFrameType::Data => {
                    if let Some(chaos_network) = chaos.as_mut()
                        && chaos_network.should_drop(VwpFrameType::Data)
                    {
                        println!("[{remote}] Chaos middleware dropped incoming Data frame");
                        continue;
                    }

                    match session.stream_receiver.ingest_data_packet(&vwp.payload) {
                        Ok(Some(decoded)) => {
                        println!(
                            "[{remote}] RaptorQ decode complete, recovered {} bytes",
                            decoded.len()
                        );

                        let stop_frames = match chunk_control_message(
                            vwp.stream_id,
                            2,
                            session.vwp_tx_seq,
                            &StreamCommand::StopStream.encode(),
                        ) {
                            Ok(frames) => frames,
                            Err(err) => {
                                println!("Failed to build STOP_STREAM frame for {remote}: {err}");
                                continue;
                            }
                        };

                        for frame in stop_frames {
                            session.vwp_tx_seq = session.vwp_tx_seq.wrapping_add(1);
                            let raw = match frame.encode() {
                                Ok(raw) => raw,
                                Err(err) => {
                                    println!("Failed to encode STOP_STREAM VWP frame: {err}");
                                    break;
                                }
                            };
                            let wire_len = match transport.write_message(&raw, &mut out_buf) {
                                Ok(len) => len,
                                Err(err) => {
                                    println!("Failed to encrypt STOP_STREAM frame: {err}");
                                    break;
                                }
                            };
                            let pkt = WirePacket {
                                version: PROTOCOL_VERSION,
                                packet_type: PacketType::Data,
                                flags: 0,
                                session_id: session.session_id,
                                seq: session.tx_seq,
                                payload: out_buf[..wire_len].to_vec(),
                            };
                            session.tx_seq += 1;
                            let pkt_raw = match pkt.encode() {
                                Ok(raw) => raw,
                                Err(err) => {
                                    println!("Failed to encode STOP_STREAM packet: {err}");
                                    break;
                                }
                            };
                            if let Err(err) = socket.send_to(&pkt_raw, remote).await {
                                println!("Failed to send STOP_STREAM packet to {remote}: {err}");
                                break;
                            }
                        }

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
                        Ok(None) => {}
                        Err(err) => {
                            println!("[{remote}] Failed to ingest data packet: {err}");
                        }
                    }
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
                stream_receiver: StreamReceiver::default(),
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

    let data_blob = b"velyx fountain stream payload for MVP demo. this data is intentionally repeated to exceed one symbol size and validate decode behavior."
        .repeat(80);
    let mut stream_sender = StreamSender::new(stream_id, &data_blob, 1300, 0, 24)?;
    let control_frames = stream_sender.stream_start_frames(1, 0)?;
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
    let mut vwp_data_seq = control_frames.len() as u32;
    let mut stop_received = false;
    let mut local_control_assembler = ControlAssembler::default();
    let mut sent_frames = 0usize;

    // Data frames start after control frame sequence space.
    stream_sender = StreamSender::new(stream_id, &data_blob, 1300, vwp_data_seq, 24)?;

    loop {
        let data_frame = stream_sender.next_data_frame();
        vwp_data_seq = data_frame.seq.wrapping_add(1);
        sent_frames += 1;

        let vwp_raw = data_frame.encode().context("encode VWP data frame")?;
        let enc_len = transport
            .write_message(&vwp_raw, &mut out_buf)
            .context("failed to encrypt VWP data frame")?;
        let data_pkt = WirePacket {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Data,
            flags: 0,
            session_id,
            seq: tx_seq,
            payload: out_buf[..enc_len].to_vec(),
        };
        tx_seq += 1;
        socket
            .send_to(&data_pkt.encode()?, remote)
            .await
            .context("failed to send raptor data frame")?;

        // MVP pacing to avoid local UDP queue overflow.
        tokio::time::sleep(Duration::from_millis(1)).await;

        let recv_result = timeout(Duration::from_millis(2), socket.recv_from(&mut in_buf)).await;
        let Ok(Ok((resp_len, from3))) = recv_result else {
            if sent_frames > 1000 && acked_chunks >= expected_acks {
                println!("No STOP_STREAM yet, continuing fire-and-forget stream...");
            }
            if sent_frames > 10000 {
                println!("MVP safety break after extended streaming window");
                break;
            }
            continue;
        };
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
            }
            VwpFrameType::Control => {
                let chunk = ControlChunk::decode(&frame.payload).context("decode control chunk")?;

                let ack = ControlAck {
                    message_id: chunk.message_id,
                    chunk_index: chunk.chunk_index,
                };
                let ack_frame = VwpFrame {
                    frame_type: VwpFrameType::Ack,
                    seq: vwp_data_seq,
                    stream_id,
                    payload: ack.encode().to_vec(),
                };

                let ack_vwp_raw = ack_frame.encode().context("encode ACK frame")?;
                let ack_wire_len = transport
                    .write_message(&ack_vwp_raw, &mut out_buf)
                    .context("encrypt ACK frame")?;
                let ack_pkt = WirePacket {
                    version: PROTOCOL_VERSION,
                    packet_type: PacketType::Data,
                    flags: 0,
                    session_id,
                    seq: tx_seq,
                    payload: out_buf[..ack_wire_len].to_vec(),
                };
                tx_seq += 1;
                socket
                    .send_to(&ack_pkt.encode()?, remote)
                    .await
                    .context("send control ACK to responder")?;

                let assembled = local_control_assembler.push_chunk(chunk)?;

                if let Some(full) = assembled {
                    match StreamCommand::decode(&full) {
                        Ok(StreamCommand::StopStream) => {
                            println!("Received STOP_STREAM from responder");
                            stop_received = true;
                        }
                        Ok(StreamCommand::StreamStart(_)) => {
                            println!("Received unexpected STREAM_START from responder");
                        }
                        Err(err) => {
                            println!("Failed to decode responder control command: {err}");
                        }
                    }
                }
            }
        }

        if stop_received && acked_chunks >= expected_acks {
            break;
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
