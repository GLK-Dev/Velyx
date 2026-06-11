use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use std::fs::OpenOptions;
use std::io::Write;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use velyx::{
    CAP_OBFS_V1, CAP_RELAY_V1, CapabilitySet, ClientFinish, ClientHello, ControlAck,
    ControlAssembler, ControlChunk, HEADER_LEN, Negotiated, PROTOCOL_VERSION, PacketType,
    ReplayWindow, ServerHello, VWP_STREAM_ID_LEN, VwpFrame, VwpFrameType, WirePacket,
    chunk_control_message, negotiate, parse_server_and_validate,
    dht::{DhtMetricsSnapshot, NodeId, RoutingTable},
};
use velyx::stream::{
    ChaosConfig, ChaosScope, DirtyNetwork, StreamCommand, StreamControlEvent, StreamReceiver,
    StreamSender, StreamTelemetry, append_metrics_csv,
};
use velyx::dht_bridge::{execute_dht_action, refresh_bucket_lookup_action, send_control_command};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const DHT_DISCOVERY_INITIAL_DELAY: Duration = Duration::from_millis(800);
const DHT_DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);
const DHT_REFRESH_CHECK_INTERVAL: Duration = Duration::from_secs(20);
const DHT_REFRESH_STALE_AFTER: Duration = Duration::from_secs(15 * 60);
const DHT_METRICS_LOG_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq)]
enum SessionState {
    Active,
    Closing,
    Closed,
}

struct RetransmitState {
    stop_stream_chunk: Vec<u8>,
    attempt: u32,
    next_retry_at: std::time::Instant,
    initial_close_time: std::time::Instant,
}

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
    last_stream_id: [u8; VWP_STREAM_ID_LEN],
    next_dht_message_id: u32,
    next_discovery_at: std::time::Instant,
    reorder_hold: Option<VwpFrame>,
    telemetry: StreamTelemetry,
    state: SessionState,
    retransmit: Option<RetransmitState>,
}

struct ResponderOptions {
    chaos: Option<ChaosConfig>,
    metrics_csv: Option<String>,
    stop_after_streams: Option<u32>,
}

struct InitiatorOptions {
    payload_size_bytes: usize,
    /// Disables 1ms inter-frame sleep for loopback benchmarks where the
    /// OS scheduler granularity would otherwise dominate run time.
    no_pacing: bool,
}

struct BenchmarkOptions {
    output_csv: String,
    max_runs: Option<u32>,
    payload_size_bytes: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        bail!("missing mode argument");
    }

    let mode = args[1].as_str();

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let local_node_id = NodeId::from_bytes(*signing_key.verifying_key().as_bytes());
    let peer_id = hex::encode(signing_key.verifying_key().as_bytes());
    println!("Velyx node started");
    println!("Peer ID (ed25519): {peer_id}");

    match mode {
        "responder" => {
            if args.len() < 3 {
                print_usage();
                bail!("responder mode needs bind address");
            }
            let bind_addr = args[2].as_str();
            let opts = parse_responder_options(&args)?;
            let chaos_middleware = match opts.chaos {
                Some(cfg) => Some(DirtyNetwork::new(cfg, 0xC0FFEE)?),
                None => None,
            };
            run_responder(
                bind_addr,
                chaos_middleware,
                opts.metrics_csv,
                opts.stop_after_streams,
                local_node_id,
            )
            .await
        }
        "initiator" => {
            if args.len() < 4 {
                print_usage();
                bail!("initiator mode needs a remote address");
            }
            let bind_addr = args[2].as_str();
            run_initiator(
                bind_addr,
                args[3].as_str(),
                InitiatorOptions {
                    payload_size_bytes: 80 * 135,
                    no_pacing: false,
                },
                local_node_id,
            )
            .await
            .map(|_| ())
        }
        "benchmark" => {
            let opts = parse_benchmark_options(&args)?;
            run_benchmark_matrix(&opts).await
        }
        _ => {
            print_usage();
            bail!("unknown mode: {mode}")
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  velyx responder <bind_addr> [chaos flags]");
    println!("  velyx initiator <bind_addr> <remote_addr>");
    println!("  velyx benchmark [output_csv] [--max-runs N] [--payload-bytes N]");
    println!("Examples:");
    println!("  velyx responder 0.0.0.0:9000");
    println!("  velyx responder 0.0.0.0:9000 --chaos-drop-data-pct 30");
    println!("  velyx responder 0.0.0.0:9000 --chaos-scope all --chaos-jitter-ms 20 --chaos-reorder-pct 10");
    println!("  velyx responder 0.0.0.0:9000 --metrics-csv ./metrics.csv --chaos-drop-data-pct 30");
    println!("  velyx initiator 0.0.0.0:0 127.0.0.1:9000");
    println!("  velyx benchmark ./whitepaper_benchmarks.csv");
    println!("  velyx benchmark ./whitepaper_benchmarks.csv --max-runs 1 --payload-bytes 262144");
}

fn parse_benchmark_options(args: &[String]) -> Result<BenchmarkOptions> {
    let mut output_csv = "whitepaper_benchmarks.csv".to_string();
    let mut max_runs = None;
    let mut payload_size_bytes = 1024 * 1024;

    let mut i = 2;
    if i < args.len() && !args[i].starts_with("--") {
        output_csv = args[i].clone();
        i += 1;
    }

    while i < args.len() {
        if i + 1 >= args.len() {
            print_usage();
            bail!("missing value for option: {}", args[i]);
        }

        match args[i].as_str() {
            "--max-runs" => {
                max_runs = Some(
                    args[i + 1]
                        .parse()
                        .with_context(|| format!("invalid --max-runs value: {}", args[i + 1]))?,
                );
            }
            "--payload-bytes" => {
                payload_size_bytes = args[i + 1]
                    .parse()
                    .with_context(|| format!("invalid --payload-bytes value: {}", args[i + 1]))?;
            }
            other => {
                print_usage();
                bail!("unknown benchmark option: {other}");
            }
        }

        i += 2;
    }

    Ok(BenchmarkOptions {
        output_csv,
        max_runs,
        payload_size_bytes,
    })
}

fn parse_responder_options(args: &[String]) -> Result<ResponderOptions> {
    if args.len() == 3 {
        return Ok(ResponderOptions {
            chaos: None,
            metrics_csv: None,
            stop_after_streams: None,
        });
    }

    let mut cfg = ChaosConfig {
        drop_data_pct: 0,
        drop_control_pct: 0,
        drop_ack_pct: 0,
        duplicate_pct: 0,
        reorder_pct: 0,
        jitter_ms: 0,
        scope: ChaosScope::DataOnly,
    };
    let mut metrics_csv = None;

    let mut i = 3;
    while i < args.len() {
        if i + 1 >= args.len() {
            print_usage();
            bail!("missing value for option: {}", args[i]);
        }

        match args[i].as_str() {
            "--chaos-drop-data-pct" => {
                cfg.drop_data_pct = parse_u8_opt("chaos-drop-data-pct", &args[i + 1])?;
            }
            "--chaos-drop-control-pct" => {
                cfg.drop_control_pct = parse_u8_opt("chaos-drop-control-pct", &args[i + 1])?;
            }
            "--chaos-drop-ack-pct" => {
                cfg.drop_ack_pct = parse_u8_opt("chaos-drop-ack-pct", &args[i + 1])?;
            }
            "--chaos-duplicate-pct" => {
                cfg.duplicate_pct = parse_u8_opt("chaos-duplicate-pct", &args[i + 1])?;
            }
            "--chaos-reorder-pct" => {
                cfg.reorder_pct = parse_u8_opt("chaos-reorder-pct", &args[i + 1])?;
            }
            "--chaos-jitter-ms" => {
                cfg.jitter_ms = args[i + 1]
                    .parse()
                    .with_context(|| format!("invalid chaos-jitter-ms: {}", args[i + 1]))?;
            }
            "--chaos-scope" => {
                cfg.scope = match args[i + 1].as_str() {
                    "data" => ChaosScope::DataOnly,
                    "all" => ChaosScope::AllFrames,
                    other => bail!("invalid chaos scope: {other}; expected data|all"),
                }
            }
            "--metrics-csv" => {
                metrics_csv = Some(args[i + 1].to_string());
            }
            other => {
                print_usage();
                bail!("unknown responder option: {other}");
            }
        }

        i += 2;
    }

    Ok(ResponderOptions {
        chaos: Some(cfg.validate()?),
        metrics_csv,
        stop_after_streams: None,
    })
}

fn parse_u8_opt(name: &str, value: &str) -> Result<u8> {
    value
        .parse()
        .with_context(|| format!("invalid {name}: {value}"))
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

fn benchmark_node_id(seed: u64) -> NodeId {
    let mut state = if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    };
    let mut bytes = [0u8; 32];
    for b in &mut bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = (state & 0xFF) as u8;
    }
    NodeId::from_bytes(bytes)
}

fn log_dht_metrics(role: &str, snapshot: DhtMetricsSnapshot) {
    let ping_success_rate = snapshot.ping_success_rate();
    let avg_nodes_per_batch = snapshot.avg_nodes_per_batch();
    let bucket_fill_ratio = snapshot.bucket_fill_ratio(20);
    let m = snapshot.metrics;
    println!(
        "[DHT][metrics][{role}] nodes={} non_empty_buckets={} max_bucket_len={} bucket_fill_ratio={:.3} ping_success_rate={:.3} avg_nodes_per_batch={:.2} inserted={} existing={} pending={} ignored={} mark_ok={} mark_miss={} replace_ok={} replace_miss={} lookup_queries={} nodes_found_batches={} nodes_found_nodes={} refresh_marked={} actions_ping={} actions_lookup={}",
        snapshot.total_nodes,
        snapshot.non_empty_buckets,
        snapshot.max_bucket_len,
        bucket_fill_ratio,
        ping_success_rate,
        avg_nodes_per_batch,
        m.insert_inserted,
        m.insert_already_present,
        m.insert_pending_ping,
        m.insert_ignored_self,
        m.mark_active_ok,
        m.mark_active_miss,
        m.replace_stale_ok,
        m.replace_stale_miss,
        m.lookup_queries,
        m.nodes_found_batches,
        m.nodes_found_nodes_total,
        m.refresh_marked,
        m.actions_generated_ping,
        m.actions_generated_lookup,
    );
}

async fn run_responder(
    bind_addr: &str,
    mut chaos: Option<DirtyNetwork>,
    metrics_csv: Option<String>,
    stop_after_streams: Option<u32>,
    local_node_id: NodeId,
) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind responder socket on {bind_addr}"))?;
    println!("Responder listening on {bind_addr}");

    let static_key = noise_private_key()?;
    let local = local_caps();
    let mut peers: HashMap<SocketAddr, PeerSession> = HashMap::new();
    let mut dht = RoutingTable::new(local_node_id, 20);
    let mut dht_routes: HashMap<NodeId, SocketAddr> = HashMap::new();
    let mut pending_dht_actions = Vec::new();
    let mut next_refresh_check = std::time::Instant::now() + DHT_REFRESH_CHECK_INTERVAL;
    let mut next_metrics_log = std::time::Instant::now() + DHT_METRICS_LOG_INTERVAL;
    let mut in_buf = [0u8; 4096];
    let mut out_buf = [0u8; 4096];
    let mut completed_streams = 0u32;

    loop {
        let recv_result = timeout(
            Duration::from_millis(50),
            socket.recv_from(&mut in_buf),
        )
        .await;

        match recv_result {
            Ok(Ok((len, remote))) => {
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

            if let Some(chaos_network) = chaos.as_mut()
                && chaos_network.should_drop(vwp.frame_type)
            {
                println!("[{remote}] Chaos middleware dropped incoming {:?} frame", vwp.frame_type);
                if vwp.frame_type == VwpFrameType::Data {
                    session.telemetry.on_data_drop();
                }
                continue;
            }

            let mut frames_to_process = Vec::new();
            if let Some(chaos_network) = chaos.as_mut()
                && chaos_network.should_reorder(vwp.frame_type)
            {
                if let Some(held) = session.reorder_hold.replace(vwp.clone()) {
                    // Process current first and delayed packet second to simulate reordering.
                    frames_to_process.push(vwp);
                    frames_to_process.push(held);
                    session.telemetry.on_data_reordered();
                } else {
                    println!("[{remote}] Chaos middleware buffered frame for reordering");
                    continue;
                }
            } else if let Some(held) = session.reorder_hold.take() {
                // Flush delayed frame after current one to keep out-of-order behavior visible.
                frames_to_process.push(vwp.clone());
                frames_to_process.push(held);
            } else {
                frames_to_process.push(vwp);
            }

            if let Some(chaos_network) = chaos.as_mut() {
                let mut duplicated = Vec::new();
                for frame in &frames_to_process {
                    if chaos_network.should_duplicate(frame.frame_type) {
                        duplicated.push(frame.clone());
                    }
                }
                if !duplicated.is_empty() {
                    println!("[{remote}] Chaos middleware duplicated {} frame(s)", duplicated.len());
                    let data_dupes = duplicated
                        .iter()
                        .filter(|f| f.frame_type == VwpFrameType::Data)
                        .count() as u64;
                    if data_dupes > 0 {
                        session.telemetry.on_data_duplicated(data_dupes);
                    }
                }
                frames_to_process.extend(duplicated);
            }

            for vwp in frames_to_process {
                if let Some(chaos_network) = chaos.as_mut()
                    && let Some(delay) = chaos_network.jitter_delay(vwp.frame_type)
                    && !delay.is_zero()
                {
                    tokio::time::sleep(delay).await;
                }

            match vwp.frame_type {
                VwpFrameType::Control => {
                    session.last_stream_id = vwp.stream_id;
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
                    session.telemetry.on_control_ack_sent();

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

                        match StreamCommand::decode(&full) {
                            Ok(StreamCommand::StreamStart(cfg)) => {
                                match session.stream_receiver.on_control_payload(&full) {
                                    Ok(StreamControlEvent::Started) => {
                                        session.telemetry.on_stream_start(cfg);
                                        println!(
                                            "[{remote}] Stream started: symbol_size={}, transfer_length={}",
                                            cfg.symbol_size(),
                                            cfg.transfer_length()
                                        );
                                    }
                                    Ok(_) => {
                                        println!("[{remote}] STREAM_START produced unexpected receiver event");
                                    }
                                    Err(err) => {
                                        println!("[{remote}] Invalid STREAM_START payload: {err}");
                                    }
                                }
                            }
                            Ok(StreamCommand::StopStream) => {
                                match session.stream_receiver.on_control_payload(&full) {
                                    Ok(StreamControlEvent::Stopped) => {
                                        println!("[{remote}] Stream stopped by remote request");
                                    }
                                    Ok(_) => {
                                        println!("[{remote}] STOP_STREAM produced unexpected receiver event");
                                    }
                                    Err(err) => {
                                        println!("[{remote}] Invalid STOP_STREAM payload: {err}");
                                    }
                                }
                            }
                            Ok(StreamCommand::Ping { sender_id }) => {
                                println!(
                                    "[{remote}] Received DHT PING sender_id={}",
                                    hex::encode(sender_id.as_bytes())
                                );
                                dht_routes.insert(sender_id, remote);
                                let insert_result = dht.insert_with_actions(sender_id);
                                pending_dht_actions.extend(insert_result.actions);

                                let message_id = session.next_dht_message_id;
                                session.next_dht_message_id = session.next_dht_message_id.wrapping_add(1);
                                if let Err(err) = send_control_command(
                                    &socket,
                                    transport,
                                    &mut out_buf,
                                    session.session_id,
                                    &mut session.tx_seq,
                                    &mut session.vwp_tx_seq,
                                    session.last_stream_id,
                                    message_id,
                                    remote,
                                    StreamCommand::Pong {
                                        sender_id: local_node_id,
                                    },
                                )
                                .await
                                {
                                    println!("[{remote}] Failed to send DHT PONG: {err}");
                                }
                            }
                            Ok(StreamCommand::Pong { sender_id }) => {
                                println!(
                                    "[{remote}] Received DHT PONG sender_id={}",
                                    hex::encode(sender_id.as_bytes())
                                );
                                dht_routes.insert(sender_id, remote);
                                let mark_result = dht.mark_active_with_actions(sender_id);
                                pending_dht_actions.extend(mark_result.actions);
                            }
                            Ok(StreamCommand::FindNode { target_id }) => {
                                println!(
                                    "[{remote}] Received DHT FIND_NODE target_id={}",
                                    hex::encode(target_id.as_bytes())
                                );

                                let closest = dht.lookup_with_metrics(target_id);
                                let message_id = session.next_dht_message_id;
                                session.next_dht_message_id =
                                    session.next_dht_message_id.wrapping_add(1);
                                if let Err(err) = send_control_command(
                                    &socket,
                                    transport,
                                    &mut out_buf,
                                    session.session_id,
                                    &mut session.tx_seq,
                                    &mut session.vwp_tx_seq,
                                    session.last_stream_id,
                                    message_id,
                                    remote,
                                    StreamCommand::NodesFound { nodes: closest },
                                )
                                .await
                                {
                                    println!("[{remote}] Failed to send DHT NODES_FOUND: {err}");
                                }
                            }
                            Ok(StreamCommand::NodesFound { nodes }) => {
                                println!(
                                    "[{remote}] Received DHT NODES_FOUND count={}",
                                    nodes.len()
                                );
                                let actions = dht.nodes_found_received(nodes);
                                pending_dht_actions.extend(actions);
                            }
                            Err(err) => {
                                println!("[{remote}] Invalid stream control payload: {err}");
                            }
                        }
                    }
                }
                VwpFrameType::Ack => {
                    let ack = match ControlAck::decode(&vwp.payload) {
                        Ok(ack) => ack,
                        Err(err) => {
                            println!("[{remote}] Failed to decode ACK: {err}");
                            continue;
                        }
                    };
                    println!("[{remote}] Received ACK: message_id={}, chunk_index={}", ack.message_id, ack.chunk_index);

                    // If we're Closing and receive an ACK for STOP_STREAM (message_id=2), move to Closed
                    if session.state == SessionState::Closing && ack.message_id == 2 {
                        println!("[{remote}] Received ACK for STOP_STREAM, moving to Closed");
                        session.state = SessionState::Closed;
                        session.retransmit = None;
                    }
                }
                VwpFrameType::Data => {
                    match session.stream_receiver.ingest_data_packet(&vwp.payload) {
                        Ok(Some(decoded)) => {
                        session.telemetry.on_data_ingested();
                        println!(
                            "[{remote}] RaptorQ decode complete, recovered {} bytes",
                            decoded.len()
                        );

                        if let Some(path) = metrics_csv.as_deref()
                            && let Some(metrics) = session
                                .telemetry
                                .finalize(remote.to_string(), session.session_id, decoded.len())
                        {
                            if let Err(err) = append_metrics_csv(path, &metrics) {
                                println!("Failed to append metrics CSV row: {err}");
                            } else {
                                println!("[{remote}] Metrics exported to {path}");
                            }
                        }

                        completed_streams = completed_streams.saturating_add(1);
                        let limit_reached = stop_after_streams
                            .map(|limit| completed_streams >= limit)
                            .unwrap_or(false);
                        if limit_reached {
                            println!("Responder reached stop-after-streams limit, initiating teardown");
                        }

                        // Transition to Closing state and prepare STOP_STREAM for reliable retransmit.
                        let stop_chunk_payload = StreamCommand::StopStream.encode();
                        let stop_frames = match chunk_control_message(
                            vwp.stream_id,
                            2,
                            session.vwp_tx_seq,
                            &stop_chunk_payload,
                        ) {
                            Ok(frames) => frames,
                            Err(err) => {
                                println!("Failed to build STOP_STREAM frame for {remote}: {err}");
                                continue;
                            }
                        };

                        // Encode first STOP_STREAM frame for retransmit storage.
                        let stop_wire_payload = if let Some(frame) = stop_frames.first() {
                            match frame.encode() {
                                Ok(raw) => {
                                    match transport.write_message(&raw, &mut out_buf) {
                                        Ok(len) => out_buf[..len].to_vec(),
                                        Err(err) => {
                                            println!("Failed to encrypt STOP_STREAM frame: {err}");
                                            continue;
                                        }
                                    }
                                }
                                Err(err) => {
                                    println!("Failed to encode STOP_STREAM VWP frame: {err}");
                                    continue;
                                }
                            }
                        } else {
                            continue;
                        };

                        // Move to Closing state with retransmit setup.
                        session.state = SessionState::Closing;
                        session.retransmit = Some(RetransmitState {
                            stop_stream_chunk: stop_wire_payload,
                            attempt: 1,
                            next_retry_at: std::time::Instant::now(),
                            initial_close_time: std::time::Instant::now(),
                        });
                        println!("[{remote}] Transitioned to Closing state, will retransmit STOP_STREAM with backoff");

                        session.vwp_tx_seq = session.vwp_tx_seq.wrapping_add(1);
                        }
                        Ok(None) => {
                            session.telemetry.on_data_ingested();
                        }
                        Err(err) => {
                            println!("[{remote}] Failed to ingest data packet: {err}");
                        }
                    }
                }
            }
            }  // close for vwp in frames_to_process
            } else {
                // New peer — must be Handshake1.
                if packet.packet_type != PacketType::Handshake1 {
                    println!("Dropping non-handshake packet from unknown peer {remote}");
                } else {
                    let params: NoiseParams = match NOISE_PATTERN.parse() {
                        Ok(p) => p,
                        Err(err) => { println!("Failed to parse noise pattern: {err}"); continue; }
                    };
                    let mut hs = match Builder::new(params)
                        .local_private_key(&static_key)
                        .build_responder()
                    {
                        Ok(h) => h,
                        Err(err) => { println!("Failed to build responder handshake: {err}"); continue; }
                    };

                    let hello1_len = match hs.read_message(&packet.payload, &mut out_buf) {
                        Ok(n) => n,
                        Err(err) => { println!("Failed to read Handshake1 from {remote}: {err}"); continue; }
                    };
                    let client_hello = match ClientHello::decode(&out_buf[..hello1_len]) {
                        Ok(h) => h,
                        Err(err) => { println!("Invalid ClientHello from {remote}: {err}"); continue; }
                    };
                    let negotiated = match negotiate(local, client_hello) {
                        Ok(n) => n,
                        Err(err) => { println!("Negotiation failed for {remote}: {err}"); continue; }
                    };
                    let server_hello = ServerHello {
                        min_version: local.min_version,
                        max_version: local.max_version,
                        caps: local.mask,
                        selected_version: negotiated.version,
                        selected_caps: negotiated.caps,
                    };
                    let hello2_len = match hs.write_message(&server_hello.encode(), &mut out_buf) {
                        Ok(n) => n,
                        Err(err) => { println!("Failed to write Handshake2 for {remote}: {err}"); continue; }
                    };
                    let session_id = packet.session_id;
                    let pkt2 = WirePacket {
                        version: PROTOCOL_VERSION,
                        packet_type: PacketType::Handshake2,
                        flags: 0,
                        session_id,
                        seq: 0,
                        payload: out_buf[..hello2_len].to_vec(),
                    };
                    let raw2 = match pkt2.encode() {
                        Ok(r) => r,
                        Err(err) => { println!("Failed to encode Handshake2 for {remote}: {err}"); continue; }
                    };
                    if let Err(err) = socket.send_to(&raw2, remote).await {
                        println!("Failed to send Handshake2 to {remote}: {err}");
                        continue;
                    }

                    let session = PeerSession {
                        session_id,
                        negotiated,
                        handshake: Some(hs),
                        transport: None,
                        tx_seq: 1,
                        recv_replay: ReplayWindow::default(),
                        vwp_tx_seq: 0,
                        stream_receiver: StreamReceiver::default(),
                        last_stream_id: [0u8; VWP_STREAM_ID_LEN],
                        next_dht_message_id: 100,
                        next_discovery_at: std::time::Instant::now() + DHT_DISCOVERY_INITIAL_DELAY,
                        control_assembler: ControlAssembler::default(),
                        reorder_hold: None,
                        telemetry: StreamTelemetry::default(),
                        state: SessionState::Active,
                        retransmit: None,
                    };
                    peers.insert(remote, session);
                    println!("New peer {remote}: handshake in progress (session_id={session_id})");
                }
            }  // close if let Some(session) else
        }
        Ok(Err(err)) => {
            println!("UDP recv_from error: {err}");
        }
        Err(_) => {
            // Timeout on recv, handle retransmits
        }
    } // close match recv_result

        let now = std::time::Instant::now();

        if !pending_dht_actions.is_empty() {
            let actions = std::mem::take(&mut pending_dht_actions);
            for action in actions {
                let Some(executed) = execute_dht_action(action, local_node_id) else {
                    continue;
                };
                let command = executed.command;
                let target_addr = if let Some(route_to) = executed.route_to {
                    let Some(addr) = dht_routes.get(&route_to).copied() else {
                        println!(
                            "Skipping DHT action: no known route for target_id={}",
                            hex::encode(route_to.as_bytes())
                        );
                        continue;
                    };
                    addr
                } else {
                    let Some(addr) = peers.iter().find_map(|(addr, sess)| {
                        (sess.state == SessionState::Active
                            && sess.transport.is_some()
                            && sess.last_stream_id != [0u8; VWP_STREAM_ID_LEN])
                            .then_some(*addr)
                    }) else {
                        println!("Skipping DHT lookup action: no active routed peers available");
                        continue;
                    };
                    addr
                };

                let Some(target_session) = peers.get_mut(&target_addr) else {
                    println!("Skipping DHT action: target session not found for {target_addr}");
                    continue;
                };
                let Some(target_transport) = target_session.transport.as_mut() else {
                    println!("Skipping DHT action: target transport not ready for {target_addr}");
                    continue;
                };
                if target_session.last_stream_id == [0u8; VWP_STREAM_ID_LEN] {
                    println!("Skipping DHT action: no stream_id known yet for {target_addr}");
                    continue;
                }

                let message_id = target_session.next_dht_message_id;
                target_session.next_dht_message_id =
                    target_session.next_dht_message_id.wrapping_add(1);

                if let Err(err) = send_control_command(
                    &socket,
                    target_transport,
                    &mut out_buf,
                    target_session.session_id,
                    &mut target_session.tx_seq,
                    &mut target_session.vwp_tx_seq,
                    target_session.last_stream_id,
                    message_id,
                    target_addr,
                    command,
                )
                .await
                {
                    println!("Failed to execute DHT action toward {target_addr}: {err}");
                }
            }
        }

        if now >= next_refresh_check {
            if let Some(bucket_idx) =
                dht.get_least_recently_refreshed_bucket_index(now, DHT_REFRESH_STALE_AFTER)
            {
                let entropy = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                let action = refresh_bucket_lookup_action(&dht, bucket_idx, entropy);
                dht.record_action_generated(action);
                pending_dht_actions.push(action);
                dht.mark_bucket_refreshed(bucket_idx);
                println!(
                    "[DHT] Refresh scheduled for bucket {} (responder)",
                    bucket_idx
                );
            }
            next_refresh_check = now + DHT_REFRESH_CHECK_INTERVAL;
        }

        if now >= next_metrics_log {
            log_dht_metrics("responder", dht.metrics_snapshot());
            next_metrics_log = now + DHT_METRICS_LOG_INTERVAL;
        }

        // Active discovery loop: periodically ask peers for nodes near our own ID.
        for (peer_addr, session) in peers.iter_mut() {
            if session.state != SessionState::Active {
                continue;
            }
            if session.last_stream_id == [0u8; VWP_STREAM_ID_LEN] {
                continue;
            }
            if now < session.next_discovery_at {
                continue;
            }

            let Some(transport) = session.transport.as_mut() else {
                continue;
            };

            let message_id = session.next_dht_message_id;
            session.next_dht_message_id = session.next_dht_message_id.wrapping_add(1);
            if let Err(err) = send_control_command(
                &socket,
                transport,
                &mut out_buf,
                session.session_id,
                &mut session.tx_seq,
                &mut session.vwp_tx_seq,
                session.last_stream_id,
                message_id,
                *peer_addr,
                StreamCommand::FindNode {
                    target_id: local_node_id,
                },
            )
            .await
            {
                println!("[{peer_addr}] Active discovery FIND_NODE send failed: {err}");
            }
            session.next_discovery_at = now + DHT_DISCOVERY_INTERVAL;
        }

        // Handle retransmits for Closing sessions
        let mut to_remove = Vec::new();
        for (peer_addr, session) in peers.iter_mut() {
            // Clean up Closed sessions
            if session.state == SessionState::Closed {
                to_remove.push(*peer_addr);
                continue;
            }

            if session.state != SessionState::Closing {
                continue;
            }

            let Some(retransmit) = session.retransmit.as_mut() else {
                continue;
            };

            let elapsed_since_close = now.duration_since(retransmit.initial_close_time);
            if elapsed_since_close > Duration::from_secs(5) {
                println!("[{peer_addr}] Hard timeout after 5 seconds in Closing state");
                to_remove.push(*peer_addr);
                continue;
            }

            if retransmit.attempt > 10 {
                println!("[{peer_addr}] Max retransmit attempts (10) reached, giving up");
                to_remove.push(*peer_addr);
                continue;
            }

            if now < retransmit.next_retry_at {
                continue;
            }

            // Calculate exponential backoff: 50ms * (1.5 ^ (attempt - 1)), capped at 300ms
            let base_ms = 50u64;
            let backoff_ms = if retransmit.attempt == 1 {
                base_ms
            } else {
                let exp = (retransmit.attempt - 1) as f64;
                let ms = (base_ms as f64 * 1.5_f64.powf(exp)) as u64;
                ms.min(300)
            };

            let pkt = WirePacket {
                version: PROTOCOL_VERSION,
                packet_type: PacketType::Data,
                flags: 0,
                session_id: session.session_id,
                seq: session.tx_seq,
                payload: retransmit.stop_stream_chunk.clone(),
            };
            session.tx_seq += 1;

            if let Ok(raw) = pkt.encode() {
                if let Err(err) = socket.send_to(&raw, peer_addr).await {
                    println!("[{peer_addr}] Failed to retransmit STOP_STREAM: {err}");
                } else {
                    println!(
                        "[{peer_addr}] Retransmit STOP_STREAM #{} (backoff in {backoff_ms}ms)",
                        retransmit.attempt
                    );
                }
            }

            retransmit.attempt += 1;
            retransmit.next_retry_at = now + Duration::from_millis(backoff_ms);
        }

        for addr in to_remove {
            println!("[{addr}] Removing session (teardown complete)");
            peers.remove(&addr);
        }

        // Exit cleanly once all sessions have completed teardown.
        if stop_after_streams.is_some()
            && completed_streams >= stop_after_streams.unwrap_or(0)
            && peers.values().all(|s| s.state != SessionState::Closing)
        {
            println!("All streams delivered and teardown complete, responder exiting");
            return Ok(());
        }
    }
}

async fn run_initiator(
    bind_addr: &str,
    remote_addr: &str,
    options: InitiatorOptions,
    local_node_id: NodeId,
) -> Result<bool> {
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

    // Retry Handshake1 with 200ms timeout until Handshake2 arrives (max 10 attempts).
    let (len2, from2) = {
        let mut attempt = 0usize;
        loop {
            match timeout(Duration::from_millis(200), socket.recv_from(&mut in_buf)).await {
                Ok(Ok((len, from))) => break (len, from),
                Ok(Err(err)) => return Err(err).context("recv_from error waiting for handshake 2"),
                Err(_) => {
                    attempt += 1;
                    if attempt >= 10 {
                        bail!("timed out waiting for handshake 2 after 10 retries");
                    }
                    // Re-send Handshake1 in case the packet was dropped.
                    socket.send_to(&raw1, remote).await.context("failed to retransmit handshake 1")?;
                }
            }
        }
    };
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

    let pattern = b"velyx benchmark stream payload block ";
    let repeats = options.payload_size_bytes.div_ceil(pattern.len());
    let mut data_blob = Vec::with_capacity(repeats * pattern.len());
    for _ in 0..repeats {
        data_blob.extend_from_slice(pattern);
    }
    data_blob.truncate(options.payload_size_bytes);
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
    let mut dht = RoutingTable::new(local_node_id, 20);
    let mut dht_routes: HashMap<NodeId, ([u8; VWP_STREAM_ID_LEN], SocketAddr)> = HashMap::new();
    let mut next_dht_message_id = 100u32;
    let mut next_discovery_at = std::time::Instant::now() + DHT_DISCOVERY_INITIAL_DELAY;
    let mut next_refresh_check = std::time::Instant::now() + DHT_REFRESH_CHECK_INTERVAL;
    let mut next_metrics_log = std::time::Instant::now() + DHT_METRICS_LOG_INTERVAL;
    let mut sent_frames = 0usize;
    let mut logged_waiting_for_stop = false;

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

        // Pacing to avoid local UDP queue overflow.
        // In benchmark mode we keep turbo throughput, but yield every 16 frames
        // to avoid socket-level burst reordering that can desync Noise counters.
        if options.no_pacing {
            if sent_frames % 16 == 0 {
                tokio::task::yield_now().await;
            }
        } else {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // Initiator-side active discovery: periodically request neighbors near self.
        let now = std::time::Instant::now();
        if now >= next_discovery_at {
            let message_id = next_dht_message_id;
            next_dht_message_id = next_dht_message_id.wrapping_add(1);
            send_control_command(
                &socket,
                &mut transport,
                &mut out_buf,
                session_id,
                &mut tx_seq,
                &mut vwp_data_seq,
                stream_id,
                message_id,
                remote,
                StreamCommand::FindNode {
                    target_id: local_node_id,
                },
            )
            .await
            .context("send periodic DHT FIND_NODE")?;
            next_discovery_at = now + DHT_DISCOVERY_INTERVAL;
        }

        if now >= next_refresh_check {
            if let Some(bucket_idx) =
                dht.get_least_recently_refreshed_bucket_index(now, DHT_REFRESH_STALE_AFTER)
            {
                let entropy = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                let action = refresh_bucket_lookup_action(&dht, bucket_idx, entropy);
                dht.record_action_generated(action);

                if let Some(executed) = execute_dht_action(action, local_node_id) {
                    let command = executed.command;
                    let (target_stream_id, target_addr) = if let Some(route_to) = executed.route_to
                    {
                        if let Some(route) = dht_routes.get(&route_to).copied() {
                            route
                        } else {
                            (stream_id, remote)
                        }
                    } else {
                        (stream_id, remote)
                    };

                    let message_id = next_dht_message_id;
                    next_dht_message_id = next_dht_message_id.wrapping_add(1);
                    send_control_command(
                        &socket,
                        &mut transport,
                        &mut out_buf,
                        session_id,
                        &mut tx_seq,
                        &mut vwp_data_seq,
                        target_stream_id,
                        message_id,
                        target_addr,
                        command,
                    )
                    .await
                    .context("send bucket refresh FIND_NODE")?;
                    dht.mark_bucket_refreshed(bucket_idx);
                    println!("[DHT] Refresh scheduled for bucket {} (initiator)", bucket_idx);
                }
            }
            next_refresh_check = now + DHT_REFRESH_CHECK_INTERVAL;
        }

        if now >= next_metrics_log {
            log_dht_metrics("initiator", dht.metrics_snapshot());
            next_metrics_log = now + DHT_METRICS_LOG_INTERVAL;
        }

        let poll_timeout = if acked_chunks >= expected_acks { 12 } else { 3 };
        let recv_result = timeout(
            Duration::from_millis(poll_timeout),
            socket.recv_from(&mut in_buf),
        )
        .await;
        let Ok(Ok((resp_len, from3))) = recv_result else {
            if sent_frames > 1200 && acked_chunks >= expected_acks && !logged_waiting_for_stop {
                println!("Waiting for STOP_STREAM after full control ACK coverage");
                logged_waiting_for_stop = true;
            }
            if sent_frames > 6000 {
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
                let control_stream_id = frame.stream_id;
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
                            println!("Received STOP_STREAM from responder, gracefully shutting down");
                            stop_received = true;
                            break;
                        }
                        Ok(StreamCommand::StreamStart(_)) => {
                            println!("Received unexpected STREAM_START from responder");
                        }
                        Ok(StreamCommand::Ping { sender_id }) => {
                            println!(
                                "Received DHT PING from responder (sender_id={})",
                                hex::encode(sender_id.as_bytes())
                            );
                            dht_routes.insert(sender_id, (control_stream_id, remote));

                            let insert_result = dht.insert_with_actions(sender_id);
                            for action in insert_result.actions {
                                let Some(executed) = execute_dht_action(action, local_node_id)
                                else {
                                    continue;
                                };
                                let command = executed.command;
                                let (target_stream_id, target_addr) =
                                    if let Some(route_to) = executed.route_to {
                                        let Some(route) = dht_routes.get(&route_to).copied() else {
                                            println!(
                                                "Skipping DHT action: no known route for target_id={}",
                                                hex::encode(route_to.as_bytes())
                                            );
                                            continue;
                                        };
                                        route
                                    } else {
                                        (control_stream_id, remote)
                                    };

                                let message_id = next_dht_message_id;
                                next_dht_message_id = next_dht_message_id.wrapping_add(1);
                                send_control_command(
                                    &socket,
                                    &mut transport,
                                    &mut out_buf,
                                    session_id,
                                    &mut tx_seq,
                                    &mut vwp_data_seq,
                                    target_stream_id,
                                    message_id,
                                    target_addr,
                                    command,
                                )
                                .await
                                .context("execute DHT action from insert result")?;
                            }

                            let message_id = next_dht_message_id;
                            next_dht_message_id = next_dht_message_id.wrapping_add(1);
                            send_control_command(
                                &socket,
                                &mut transport,
                                &mut out_buf,
                                session_id,
                                &mut tx_seq,
                                &mut vwp_data_seq,
                                control_stream_id,
                                message_id,
                                remote,
                                StreamCommand::Pong {
                                    sender_id: local_node_id,
                                },
                            )
                            .await
                            .context("send DHT PONG")?;
                        }
                        Ok(StreamCommand::Pong { sender_id }) => {
                            println!(
                                "Received DHT PONG from responder (sender_id={})",
                                hex::encode(sender_id.as_bytes())
                            );
                            dht_routes.insert(sender_id, (control_stream_id, remote));

                            let mark_result = dht.mark_active_with_actions(sender_id);
                            for action in mark_result.actions {
                                let Some(executed) = execute_dht_action(action, local_node_id)
                                else {
                                    continue;
                                };
                                let command = executed.command;
                                let (target_stream_id, target_addr) =
                                    if let Some(route_to) = executed.route_to {
                                        let Some(route) = dht_routes.get(&route_to).copied() else {
                                            println!(
                                                "Skipping DHT action: no known route for target_id={}",
                                                hex::encode(route_to.as_bytes())
                                            );
                                            continue;
                                        };
                                        route
                                    } else {
                                        (control_stream_id, remote)
                                    };

                                let message_id = next_dht_message_id;
                                next_dht_message_id = next_dht_message_id.wrapping_add(1);
                                send_control_command(
                                    &socket,
                                    &mut transport,
                                    &mut out_buf,
                                    session_id,
                                    &mut tx_seq,
                                    &mut vwp_data_seq,
                                    target_stream_id,
                                    message_id,
                                    target_addr,
                                    command,
                                )
                                .await
                                .context("execute DHT action from mark_active result")?;
                            }
                        }
                        Ok(StreamCommand::FindNode { target_id }) => {
                            println!(
                                "Received DHT FIND_NODE from responder (target_id={})",
                                hex::encode(target_id.as_bytes())
                            );

                            let closest = dht.lookup_with_metrics(target_id);
                            let message_id = next_dht_message_id;
                            next_dht_message_id = next_dht_message_id.wrapping_add(1);
                            send_control_command(
                                &socket,
                                &mut transport,
                                &mut out_buf,
                                session_id,
                                &mut tx_seq,
                                &mut vwp_data_seq,
                                control_stream_id,
                                message_id,
                                remote,
                                StreamCommand::NodesFound { nodes: closest },
                            )
                            .await
                            .context("send DHT NODES_FOUND")?;
                        }
                        Ok(StreamCommand::NodesFound { nodes }) => {
                            println!(
                                "Received DHT NODES_FOUND from responder (count={})",
                                nodes.len()
                            );

                            let actions = dht.nodes_found_received(nodes);
                            for action in actions {
                                let Some(executed) = execute_dht_action(action, local_node_id)
                                else {
                                    continue;
                                };
                                let command = executed.command;
                                let (target_stream_id, target_addr) =
                                    if let Some(route_to) = executed.route_to {
                                        let Some(route) = dht_routes.get(&route_to).copied() else {
                                            println!(
                                                "Skipping DHT action: no known route for target_id={}",
                                                hex::encode(route_to.as_bytes())
                                            );
                                            continue;
                                        };
                                        route
                                    } else {
                                        (control_stream_id, remote)
                                    };

                                let message_id = next_dht_message_id;
                                next_dht_message_id = next_dht_message_id.wrapping_add(1);
                                send_control_command(
                                    &socket,
                                    &mut transport,
                                    &mut out_buf,
                                    session_id,
                                    &mut tx_seq,
                                    &mut vwp_data_seq,
                                    target_stream_id,
                                    message_id,
                                    target_addr,
                                    command,
                                )
                                .await
                                .context("execute DHT action from nodes_found result")?;
                            }
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

    Ok(stop_received)
}

async fn run_benchmark_matrix(options: &BenchmarkOptions) -> Result<()> {
    let losses = [0u8, 10, 20, 30, 40, 50];
    let jitters = [0u16, 10, 50];
    let reorders = [0u8, 10, 25];

    initialize_benchmark_csv(&options.output_csv)?;
    let mut run_id = 0u32;

    for loss in losses {
        for jitter in jitters {
            for reorder in reorders {
                run_id += 1;
                if let Some(max) = options.max_runs
                    && run_id > max
                {
                    println!("Benchmark matrix stopped after max-runs={max}");
                    println!("Partial benchmark output: {}", options.output_csv);
                    return Ok(());
                }
                let port = 12000 + run_id as u16;
                let bind_addr = format!("127.0.0.1:{port}");
                let remote_addr = bind_addr.clone();
                let per_run_metrics = format!("bench_run_{run_id}.csv");
                if Path::new(&per_run_metrics).exists() {
                    std::fs::remove_file(&per_run_metrics)
                        .with_context(|| format!("failed to remove old file {per_run_metrics}"))?;
                }

                let chaos_cfg = ChaosConfig {
                    drop_data_pct: loss,
                    drop_control_pct: 0,
                    drop_ack_pct: 0,
                    duplicate_pct: 0,
                    reorder_pct: reorder,
                    jitter_ms: jitter,
                    scope: ChaosScope::DataOnly,
                }
                .validate()?;

                let responder = tokio::spawn({
                    let bind_addr = bind_addr.clone();
                    let metrics_path = per_run_metrics.clone();
                    let responder_node_id = benchmark_node_id((run_id as u64) << 1);
                    async move {
                        let dirty = Some(DirtyNetwork::new(chaos_cfg, 0xBADC0DE + run_id as u64)?);
                        run_responder(&bind_addr, dirty, Some(metrics_path), Some(1), responder_node_id).await
                    }
                });

                tokio::time::sleep(Duration::from_millis(50)).await;

                let bench_started = std::time::Instant::now();
                let initiator_result = run_initiator(
                    "127.0.0.1:0",
                    &remote_addr,
                    InitiatorOptions {
                        payload_size_bytes: options.payload_size_bytes,
                        no_pacing: false,
                    },
                    benchmark_node_id(((run_id as u64) << 1) | 1),
                )
                .await;

                let initiator_ok = match initiator_result {
                    Ok(stop_ok) => stop_ok,
                    Err(err) => {
                        println!("Benchmark run {run_id}: initiator error: {err}");
                        false
                    }
                };

                let responder_ok = match timeout(Duration::from_secs(6), responder).await {
                    Ok(joined) => match joined {
                        Ok(result) => result.is_ok(),
                        Err(err) => {
                            println!("Benchmark run {run_id}: responder join error: {err}");
                            false
                        }
                    },
                    Err(_) => {
                        println!("Benchmark run {run_id}: responder timeout, aborting task");
                        false
                    }
                };

                let elapsed_ms = bench_started.elapsed().as_millis();
                let metrics = parse_last_metrics_row(&per_run_metrics)?;

                append_benchmark_row(
                    &options.output_csv,
                    run_id,
                    loss,
                    jitter,
                    reorder,
                    initiator_ok,
                    responder_ok,
                    elapsed_ms,
                    metrics,
                )?;

                if Path::new(&per_run_metrics).exists() {
                    let _ = std::fs::remove_file(&per_run_metrics);
                }

                println!(
                    "Benchmark run #{run_id} completed (loss={loss} jitter={jitter} reorder={reorder})"
                );
            }
        }
    }

    // AllFrames stress profiles — named real-world network scenarios.
    // These validate STOP_STREAM retransmit reliability under total chaos.
    struct NetworkProfile {
        name: &'static str,
        loss: u8,
        jitter: u16,
        reorder: u8,
    }
    let allframes_profiles = [
        NetworkProfile { name: "mobile_3g_edge",    loss: 10, jitter: 50, reorder:  0 },
        NetworkProfile { name: "congested_wifi",    loss: 20, jitter: 10, reorder: 10 },
        NetworkProfile { name: "starlink_storm",    loss: 30, jitter: 20, reorder: 25 },
        NetworkProfile { name: "datacenter_flap",  loss:  5, jitter:  5, reorder:  5 },
    ];

    for profile in &allframes_profiles {
        run_id += 1;
        if let Some(max) = options.max_runs
            && run_id > max
        {
            println!("Benchmark matrix stopped after max-runs={max}");
            println!("Partial benchmark output: {}", options.output_csv);
            return Ok(());
        }

        let port = 12000 + run_id as u16;
        let bind_addr = format!("127.0.0.1:{port}");
        let remote_addr = bind_addr.clone();
        let per_run_metrics = format!("bench_run_{run_id}.csv");
        if Path::new(&per_run_metrics).exists() {
            std::fs::remove_file(&per_run_metrics)
                .with_context(|| format!("failed to remove old file {per_run_metrics}"))?;
        }

        let chaos_cfg = ChaosConfig {
            drop_data_pct: profile.loss,
            drop_control_pct: profile.loss,  // AllFrames: control/ack also affected
            drop_ack_pct: profile.loss,
            duplicate_pct: 0,
            reorder_pct: profile.reorder,
            jitter_ms: profile.jitter,
            scope: ChaosScope::AllFrames,
        }
        .validate()?;

        println!(
            "AllFrames profile '{}': loss={}% jitter={}ms reorder={}%",
            profile.name, profile.loss, profile.jitter, profile.reorder
        );

        let responder = tokio::spawn({
            let bind_addr = bind_addr.clone();
            let metrics_path = per_run_metrics.clone();
            let responder_node_id = benchmark_node_id((run_id as u64) << 1);
            async move {
                let dirty = Some(DirtyNetwork::new(chaos_cfg, 0xDEAD0000 + run_id as u64)?);
                run_responder(&bind_addr, dirty, Some(metrics_path), Some(1), responder_node_id).await
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let bench_started = std::time::Instant::now();
        let initiator_result = run_initiator(
            "127.0.0.1:0",
            &remote_addr,
            InitiatorOptions {
                payload_size_bytes: options.payload_size_bytes,
                no_pacing: false,
            },
            benchmark_node_id(((run_id as u64) << 1) | 1),
        )
        .await;

        let initiator_ok = match initiator_result {
            Ok(stop_ok) => stop_ok,
            Err(err) => {
                println!("Benchmark run {run_id} ({}): initiator error: {err}", profile.name);
                false
            }
        };

        let responder_ok = match timeout(Duration::from_secs(15), responder).await {
            Ok(joined) => match joined {
                Ok(result) => result.is_ok(),
                Err(err) => {
                    println!("Benchmark run {run_id} ({}): responder join error: {err}", profile.name);
                    false
                }
            },
            Err(_) => {
                println!("Benchmark run {run_id} ({}): responder timeout", profile.name);
                false
            }
        };

        let elapsed_ms = bench_started.elapsed().as_millis();
        let metrics = parse_last_metrics_row(&per_run_metrics)?;

        append_benchmark_row(
            &options.output_csv,
            run_id,
            profile.loss,
            profile.jitter,
            profile.reorder,
            initiator_ok,
            responder_ok,
            elapsed_ms,
            metrics,
        )?;

        if Path::new(&per_run_metrics).exists() {
            let _ = std::fs::remove_file(&per_run_metrics);
        }

        println!(
            "Benchmark run #{run_id} ({}) completed: initiator_ok={initiator_ok} responder_ok={responder_ok}",
            profile.name
        );
    }

    println!("Benchmark matrix complete. Output: {}", options.output_csv);
    Ok(())
}

fn initialize_benchmark_csv(path: &str) -> Result<()> {
    if Path::new(path).exists() {
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to create benchmark CSV: {path}"))?;
    writeln!(
        file,
        "run_id,loss_pct,jitter_ms,reorder_pct,initiator_ok,responder_ok,end_to_end_ms,recovery_time_ms,goodput_bytes_per_sec,overhead_ratio,data_frames_dropped,data_frames_duplicated,data_frames_reordered"
    )
    .context("failed to write benchmark CSV header")?;
    Ok(())
}

type ParsedMetrics = Option<(u128, f64, f64, u64, u64, u64)>;

fn parse_last_metrics_row(path: &str) -> Result<ParsedMetrics> {
    if !Path::new(path).exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read metrics CSV: {path}"))?;
    let mut lines = content.lines();
    let _header = lines.next();
    let Some(last) = lines.last() else {
        return Ok(None);
    };

    let parts: Vec<&str> = last.split(',').collect();
    if parts.len() < 14 {
        return Ok(None);
    }

    let recovery_time_ms = parts[11].parse().unwrap_or(0);
    let goodput_bps = parts[12].parse().unwrap_or(0.0);
    let overhead_ratio = parts[13].parse().unwrap_or(0.0);
    let dropped = parts[7].parse().unwrap_or(0);
    let duplicated = parts[8].parse().unwrap_or(0);
    let reordered = parts[9].parse().unwrap_or(0);

    Ok(Some((
        recovery_time_ms,
        goodput_bps,
        overhead_ratio,
        dropped,
        duplicated,
        reordered,
    )))
}

#[allow(clippy::too_many_arguments)]
fn append_benchmark_row(
    path: &str,
    run_id: u32,
    loss_pct: u8,
    jitter_ms: u16,
    reorder_pct: u8,
    initiator_ok: bool,
    responder_ok: bool,
    end_to_end_ms: u128,
    metrics: ParsedMetrics,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open benchmark CSV: {path}"))?;

    let (recovery_ms, goodput, overhead, dropped, duped, reordered) =
        metrics.unwrap_or((0, 0.0, 0.0, 0, 0, 0));

    writeln!(
        file,
        "{},{},{},{},{},{},{},{},{:.2},{:.4},{},{},{}",
        run_id,
        loss_pct,
        jitter_ms,
        reorder_pct,
        initiator_ok,
        responder_ok,
        end_to_end_ms,
        recovery_ms,
        goodput,
        overhead,
        dropped,
        duped,
        reordered,
    )
    .context("failed to append benchmark CSV row")?;
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
