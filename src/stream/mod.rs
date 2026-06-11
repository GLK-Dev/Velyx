use anyhow::{Context, Result, bail};
use raptorq::{Decoder as RaptorDecoder, Encoder as RaptorEncoder, EncodingPacket, ObjectTransmissionInformation};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::{
    VWP_STREAM_ID_LEN, VwpFrame, VwpFrameType, chunk_control_message,
    dht::{ContentKey, NodeId},
};

pub const CMD_STREAM_START: u8 = 1;
pub const CMD_STOP_STREAM: u8 = 2;
pub const CMD_DHT_PING: u8 = 3;
pub const CMD_DHT_PONG: u8 = 4;
pub const CMD_DHT_FIND_NODE: u8 = 5;
pub const CMD_DHT_NODES_FOUND: u8 = 6;
pub const CMD_DHT_STORE_PROVIDER: u8 = 7;
pub const CMD_DHT_FIND_VALUE: u8 = 8;
pub const CMD_DHT_VALUE_FOUND: u8 = 9;
pub const CMD_DHT_NODE_ID_LEN: usize = 1 + 32;
pub const CMD_DHT_STORE_PROVIDER_LEN: usize = 1 + 32 + 32;
pub const CMD_DHT_FIND_VALUE_LEN: usize = 1 + 32;
pub const DHT_NODE_ID_BYTES: usize = 32;
pub const DHT_CONTENT_KEY_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub enum StreamCommand {
    StreamStart(ObjectTransmissionInformation),
    StopStream,
    Ping { sender_id: NodeId },
    Pong { sender_id: NodeId },
    FindNode { target_id: NodeId },
    NodesFound { nodes: Vec<NodeId> },
    StoreProvider {
        key: ContentKey,
        provider_id: NodeId,
    },
    FindValue { key: ContentKey },
    ValueFound {
        key: ContentKey,
        providers: Vec<NodeId>,
    },
}

fn serialize_nodes(nodes: &[NodeId]) -> Vec<u8> {
    let count = nodes.len().min(u8::MAX as usize);
    let mut out = Vec::with_capacity(1 + count * DHT_NODE_ID_BYTES);
    out.push(count as u8);
    for node in nodes.iter().take(count) {
        out.extend_from_slice(node.as_bytes());
    }
    out
}

fn deserialize_nodes(payload: &[u8]) -> Result<Vec<NodeId>> {
    if payload.is_empty() {
        bail!("NODES_FOUND payload missing length byte");
    }

    let count = payload[0] as usize;
    let expected = 1 + count * DHT_NODE_ID_BYTES;
    if payload.len() != expected {
        bail!(
            "invalid NODES_FOUND payload length: got {}, expected {}",
            payload.len(),
            expected
        );
    }

    let mut nodes = Vec::with_capacity(count);
    let mut offset = 1;
    for _ in 0..count {
        let mut id = [0u8; DHT_NODE_ID_BYTES];
        id.copy_from_slice(&payload[offset..offset + DHT_NODE_ID_BYTES]);
        nodes.push(NodeId::from_bytes(id));
        offset += DHT_NODE_ID_BYTES;
    }
    Ok(nodes)
}

impl StreamCommand {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::StreamStart(config) => {
                let mut payload = Vec::with_capacity(13);
                payload.push(CMD_STREAM_START);
                payload.extend_from_slice(&config.serialize());
                payload
            }
            Self::StopStream => vec![CMD_STOP_STREAM],
            Self::Ping { sender_id } => {
                let mut payload = Vec::with_capacity(CMD_DHT_NODE_ID_LEN);
                payload.push(CMD_DHT_PING);
                payload.extend_from_slice(sender_id.as_bytes());
                payload
            }
            Self::Pong { sender_id } => {
                let mut payload = Vec::with_capacity(CMD_DHT_NODE_ID_LEN);
                payload.push(CMD_DHT_PONG);
                payload.extend_from_slice(sender_id.as_bytes());
                payload
            }
            Self::FindNode { target_id } => {
                let mut payload = Vec::with_capacity(CMD_DHT_NODE_ID_LEN);
                payload.push(CMD_DHT_FIND_NODE);
                payload.extend_from_slice(target_id.as_bytes());
                payload
            }
            Self::NodesFound { nodes } => {
                let mut payload = Vec::with_capacity(2 + nodes.len() * DHT_NODE_ID_BYTES);
                payload.push(CMD_DHT_NODES_FOUND);
                payload.extend_from_slice(&serialize_nodes(nodes));
                payload
            }
            Self::StoreProvider { key, provider_id } => {
                let mut payload = Vec::with_capacity(CMD_DHT_STORE_PROVIDER_LEN);
                payload.push(CMD_DHT_STORE_PROVIDER);
                payload.extend_from_slice(key.as_bytes());
                payload.extend_from_slice(provider_id.as_bytes());
                payload
            }
            Self::FindValue { key } => {
                let mut payload = Vec::with_capacity(CMD_DHT_FIND_VALUE_LEN);
                payload.push(CMD_DHT_FIND_VALUE);
                payload.extend_from_slice(key.as_bytes());
                payload
            }
            Self::ValueFound { key, providers } => {
                let mut payload =
                    Vec::with_capacity(1 + DHT_CONTENT_KEY_BYTES + 1 + providers.len() * DHT_NODE_ID_BYTES);
                payload.push(CMD_DHT_VALUE_FOUND);
                payload.extend_from_slice(key.as_bytes());
                payload.extend_from_slice(&serialize_nodes(providers));
                payload
            }
        }
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        if payload.is_empty() {
            bail!("empty stream command payload");
        }

        match payload[0] {
            CMD_STREAM_START => {
                if payload.len() != 13 {
                    bail!("invalid STREAM_START payload length: {}", payload.len());
                }
                let mut oti = [0u8; 12];
                oti.copy_from_slice(&payload[1..13]);
                Ok(Self::StreamStart(ObjectTransmissionInformation::deserialize(
                    &oti,
                )))
            }
            CMD_STOP_STREAM => {
                if payload.len() != 1 {
                    bail!("invalid STOP_STREAM payload length: {}", payload.len());
                }
                Ok(Self::StopStream)
            }
            CMD_DHT_PING => {
                if payload.len() != CMD_DHT_NODE_ID_LEN {
                    bail!("invalid DHT_PING payload length: {}", payload.len());
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&payload[1..CMD_DHT_NODE_ID_LEN]);
                Ok(Self::Ping {
                    sender_id: NodeId::from_bytes(id),
                })
            }
            CMD_DHT_PONG => {
                if payload.len() != CMD_DHT_NODE_ID_LEN {
                    bail!("invalid DHT_PONG payload length: {}", payload.len());
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&payload[1..CMD_DHT_NODE_ID_LEN]);
                Ok(Self::Pong {
                    sender_id: NodeId::from_bytes(id),
                })
            }
            CMD_DHT_FIND_NODE => {
                if payload.len() != CMD_DHT_NODE_ID_LEN {
                    bail!("invalid DHT_FIND_NODE payload length: {}", payload.len());
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&payload[1..CMD_DHT_NODE_ID_LEN]);
                Ok(Self::FindNode {
                    target_id: NodeId::from_bytes(id),
                })
            }
            CMD_DHT_NODES_FOUND => {
                let nodes = deserialize_nodes(&payload[1..])?;
                Ok(Self::NodesFound { nodes })
            }
            CMD_DHT_STORE_PROVIDER => {
                if payload.len() != CMD_DHT_STORE_PROVIDER_LEN {
                    bail!(
                        "invalid DHT_STORE_PROVIDER payload length: {}",
                        payload.len()
                    );
                }

                let mut key = [0u8; DHT_CONTENT_KEY_BYTES];
                key.copy_from_slice(&payload[1..1 + DHT_CONTENT_KEY_BYTES]);

                let mut provider_id = [0u8; DHT_NODE_ID_BYTES];
                provider_id.copy_from_slice(
                    &payload[1 + DHT_CONTENT_KEY_BYTES..1 + DHT_CONTENT_KEY_BYTES + DHT_NODE_ID_BYTES],
                );

                Ok(Self::StoreProvider {
                    key: ContentKey::from_bytes(key),
                    provider_id: NodeId::from_bytes(provider_id),
                })
            }
            CMD_DHT_FIND_VALUE => {
                if payload.len() != CMD_DHT_FIND_VALUE_LEN {
                    bail!("invalid DHT_FIND_VALUE payload length: {}", payload.len());
                }

                let mut key = [0u8; DHT_CONTENT_KEY_BYTES];
                key.copy_from_slice(&payload[1..1 + DHT_CONTENT_KEY_BYTES]);

                Ok(Self::FindValue {
                    key: ContentKey::from_bytes(key),
                })
            }
            CMD_DHT_VALUE_FOUND => {
                if payload.len() < 2 + DHT_CONTENT_KEY_BYTES {
                    bail!("invalid DHT_VALUE_FOUND payload length: {}", payload.len());
                }

                let mut key = [0u8; DHT_CONTENT_KEY_BYTES];
                key.copy_from_slice(&payload[1..1 + DHT_CONTENT_KEY_BYTES]);
                let providers = deserialize_nodes(&payload[1 + DHT_CONTENT_KEY_BYTES..])?;

                Ok(Self::ValueFound {
                    key: ContentKey::from_bytes(key),
                    providers,
                })
            }
            other => bail!("unknown stream command: {other}"),
        }
    }
}

pub struct StreamSender {
    packets: Vec<Vec<u8>>,
    next_packet: usize,
    next_seq: u32,
    stream_start: StreamCommand,
    stream_id: [u8; VWP_STREAM_ID_LEN],
}

impl StreamSender {
    pub fn new(
        stream_id: [u8; VWP_STREAM_ID_LEN],
        data: &[u8],
        mtu: u16,
        initial_data_seq: u32,
        repair_packets_per_block: u32,
    ) -> Result<Self> {
        let encoder = RaptorEncoder::with_defaults(data, mtu);
        let config = encoder.get_config();
        let packets = encoder
            .get_encoded_packets(repair_packets_per_block)
            .into_iter()
            .map(|p| p.serialize())
            .collect::<Vec<_>>();

        if packets.is_empty() {
            bail!("raptor encoder produced no packets");
        }

        Ok(Self {
            packets,
            next_packet: 0,
            next_seq: initial_data_seq,
            stream_start: StreamCommand::StreamStart(config),
            stream_id,
        })
    }

    pub fn stream_start_frames(&self, message_id: u32, start_seq: u32) -> Result<Vec<VwpFrame>> {
        let payload = self.stream_start.encode();
        chunk_control_message(self.stream_id, message_id, start_seq, &payload)
            .context("failed to chunk STREAM_START control payload")
    }

    pub fn next_data_frame(&mut self) -> VwpFrame {
        let payload = self.packets[self.next_packet % self.packets.len()].clone();
        self.next_packet = (self.next_packet + 1) % self.packets.len();

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        VwpFrame {
            frame_type: VwpFrameType::Data,
            seq,
            stream_id: self.stream_id,
            payload,
        }
    }
}

#[derive(Default)]
pub struct StreamReceiver {
    decoder: Option<RaptorDecoder>,
    done: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamControlEvent {
    Started,
    Stopped,
    Ignored,
}

impl StreamReceiver {
    pub fn on_control_payload(&mut self, payload: &[u8]) -> Result<StreamControlEvent> {
        let cmd = StreamCommand::decode(payload)?;
        match cmd {
            StreamCommand::StreamStart(config) => {
                self.decoder = Some(RaptorDecoder::new(config));
                self.done = false;
                Ok(StreamControlEvent::Started)
            }
            StreamCommand::StopStream => {
                self.done = true;
                self.decoder = None;
                Ok(StreamControlEvent::Stopped)
            }
            StreamCommand::Ping { .. }
            | StreamCommand::Pong { .. }
            | StreamCommand::FindNode { .. }
            | StreamCommand::NodesFound { .. }
            | StreamCommand::StoreProvider { .. }
            | StreamCommand::FindValue { .. }
            | StreamCommand::ValueFound { .. } => Ok(StreamControlEvent::Ignored),
        }
    }

    pub fn ingest_data_packet(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.done {
            return Ok(None);
        }

        let Some(decoder) = self.decoder.as_mut() else {
            return Ok(None);
        };

        if payload.len() < 4 {
            bail!("raptor payload too short");
        }

        let packet = EncodingPacket::deserialize(payload);
        let decoded = decoder.decode(packet);
        if decoded.is_some() {
            self.done = true;
        }
        Ok(decoded)
    }

    pub fn is_done(&self) -> bool {
        self.done
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ChaosScope {
    DataOnly,
    AllFrames,
}

#[derive(Debug, Clone, Copy)]
pub struct ChaosConfig {
    pub drop_data_pct: u8,
    pub drop_control_pct: u8,
    pub drop_ack_pct: u8,
    pub duplicate_pct: u8,
    pub reorder_pct: u8,
    pub jitter_ms: u16,
    pub scope: ChaosScope,
}

impl ChaosConfig {
    pub fn validate(self) -> Result<Self> {
        for (label, value) in [
            ("drop_data_pct", self.drop_data_pct),
            ("drop_control_pct", self.drop_control_pct),
            ("drop_ack_pct", self.drop_ack_pct),
            ("duplicate_pct", self.duplicate_pct),
            ("reorder_pct", self.reorder_pct),
        ] {
            if value > 100 {
                bail!("{label} must be <= 100, got {value}");
            }
        }
        Ok(self)
    }
}

pub struct DirtyNetwork {
    config: ChaosConfig,
    state: u64,
}

#[derive(Debug, Clone)]
pub struct StreamMetrics {
    pub finished_at_unix_ms: u128,
    pub peer: String,
    pub session_id: u64,
    pub transfer_length: u64,
    pub symbol_size: u16,
    pub min_symbols_required: u64,
    pub data_frames_ingested: u64,
    pub data_frames_dropped: u64,
    pub data_frames_duplicated: u64,
    pub data_frames_reordered: u64,
    pub control_acks_sent: u64,
    pub recovery_time_ms: u128,
    pub goodput_bytes_per_sec: f64,
    pub overhead_ratio: f64,
}

#[derive(Debug, Default)]
pub struct StreamTelemetry {
    start_at: Option<Instant>,
    transfer_length: u64,
    symbol_size: u16,
    min_symbols_required: u64,
    data_frames_ingested: u64,
    data_frames_dropped: u64,
    data_frames_duplicated: u64,
    data_frames_reordered: u64,
    control_acks_sent: u64,
}

impl StreamTelemetry {
    pub fn on_stream_start(&mut self, config: ObjectTransmissionInformation) {
        self.start_at = Some(Instant::now());
        self.transfer_length = config.transfer_length();
        self.symbol_size = config.symbol_size();
        self.min_symbols_required = self.transfer_length.div_ceil(self.symbol_size as u64);
        self.data_frames_ingested = 0;
        self.data_frames_dropped = 0;
        self.data_frames_duplicated = 0;
        self.data_frames_reordered = 0;
        self.control_acks_sent = 0;
    }

    pub fn on_data_ingested(&mut self) {
        self.data_frames_ingested += 1;
    }

    pub fn on_data_drop(&mut self) {
        self.data_frames_dropped += 1;
    }

    pub fn on_data_duplicated(&mut self, count: u64) {
        self.data_frames_duplicated += count;
    }

    pub fn on_data_reordered(&mut self) {
        self.data_frames_reordered += 1;
    }

    pub fn on_control_ack_sent(&mut self) {
        self.control_acks_sent += 1;
    }

    pub fn finalize(&self, peer: String, session_id: u64, decoded_bytes: usize) -> Option<StreamMetrics> {
        let started = self.start_at?;
        let recovery_time_ms = started.elapsed().as_millis();
        let seconds = (recovery_time_ms as f64 / 1000.0).max(0.001);
        let goodput_bytes_per_sec = decoded_bytes as f64 / seconds;
        let overhead_ratio = if self.min_symbols_required == 0 {
            0.0
        } else {
            self.data_frames_ingested as f64 / self.min_symbols_required as f64
        };

        let finished_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        Some(StreamMetrics {
            finished_at_unix_ms,
            peer,
            session_id,
            transfer_length: self.transfer_length,
            symbol_size: self.symbol_size,
            min_symbols_required: self.min_symbols_required,
            data_frames_ingested: self.data_frames_ingested,
            data_frames_dropped: self.data_frames_dropped,
            data_frames_duplicated: self.data_frames_duplicated,
            data_frames_reordered: self.data_frames_reordered,
            control_acks_sent: self.control_acks_sent,
            recovery_time_ms,
            goodput_bytes_per_sec,
            overhead_ratio,
        })
    }
}

pub fn append_metrics_csv(path: &str, metrics: &StreamMetrics) -> Result<()> {
    let file_exists = std::path::Path::new(path).exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open metrics CSV path: {path}"))?;

    if !file_exists {
        writeln!(
            file,
            "finished_at_unix_ms,peer,session_id,transfer_length,symbol_size,min_symbols_required,data_frames_ingested,data_frames_dropped,data_frames_duplicated,data_frames_reordered,control_acks_sent,recovery_time_ms,goodput_bytes_per_sec,overhead_ratio"
        )
        .context("failed to write CSV header")?;
    }

    writeln!(
        file,
        "{},{},{},{},{},{},{},{},{},{},{},{},{:.2},{:.4}",
        metrics.finished_at_unix_ms,
        metrics.peer,
        metrics.session_id,
        metrics.transfer_length,
        metrics.symbol_size,
        metrics.min_symbols_required,
        metrics.data_frames_ingested,
        metrics.data_frames_dropped,
        metrics.data_frames_duplicated,
        metrics.data_frames_reordered,
        metrics.control_acks_sent,
        metrics.recovery_time_ms,
        metrics.goodput_bytes_per_sec,
        metrics.overhead_ratio,
    )
    .context("failed to write CSV row")?;

    Ok(())
}

impl DirtyNetwork {
    pub fn new(config: ChaosConfig, seed: u64) -> Result<Self> {
        Ok(Self {
            config: config.validate()?,
            state: if seed == 0 { 0xA5A5_1337_55AA_F00D } else { seed },
        })
    }

    pub fn should_drop(&mut self, frame_type: VwpFrameType) -> bool {
        if !self.is_in_scope(frame_type) {
            return false;
        }

        let pct = match frame_type {
            VwpFrameType::Data => self.config.drop_data_pct,
            VwpFrameType::Control => self.config.drop_control_pct,
            VwpFrameType::Ack => self.config.drop_ack_pct,
        };

        if pct == 0 {
            return false;
        }

        self.roll_pct(pct)
    }

    pub fn should_duplicate(&mut self, frame_type: VwpFrameType) -> bool {
        if !self.is_in_scope(frame_type) || self.config.duplicate_pct == 0 {
            return false;
        }
        self.roll_pct(self.config.duplicate_pct)
    }

    pub fn should_reorder(&mut self, frame_type: VwpFrameType) -> bool {
        if !self.is_in_scope(frame_type) || self.config.reorder_pct == 0 {
            return false;
        }
        self.roll_pct(self.config.reorder_pct)
    }

    pub fn jitter_delay(&mut self, frame_type: VwpFrameType) -> Option<Duration> {
        if !self.is_in_scope(frame_type) || self.config.jitter_ms == 0 {
            return None;
        }

        // Uniform delay in [0, jitter_ms].
        let upper = self.config.jitter_ms as u32;
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        let sample = ((self.state >> 32) as u32) % (upper + 1);
        Some(Duration::from_millis(sample as u64))
    }

    fn is_in_scope(&self, frame_type: VwpFrameType) -> bool {
        match self.config.scope {
            ChaosScope::DataOnly => frame_type == VwpFrameType::Data,
            ChaosScope::AllFrames => true,
        }
    }

    fn roll_pct(&mut self, pct: u8) -> bool {
        if pct == 0 {
            return false;
        }

        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        let sample = ((self.state >> 32) as u32) % 100;
        sample < pct as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlChunk;

    #[test]
    fn chaos_monkey_50_percent_loss_still_recovers() {
        let mut stream_id = [0u8; VWP_STREAM_ID_LEN];
        stream_id[0] = 9;
        let data = b"velyx-chaos-monkey-raptorq".repeat(1024);

        let mut sender = StreamSender::new(stream_id, &data, 1300, 0, 32).expect("sender");
        let mut receiver = StreamReceiver::default();
        let mut chaos = DirtyNetwork::new(
            ChaosConfig {
                drop_data_pct: 50,
                drop_control_pct: 0,
                drop_ack_pct: 0,
                duplicate_pct: 0,
                reorder_pct: 0,
                jitter_ms: 0,
                scope: ChaosScope::DataOnly,
            },
            42,
        )
        .expect("chaos");

        let start_payload = sender
            .stream_start
            .encode();
        receiver
            .on_control_payload(&start_payload)
            .expect("stream start");

        let mut decoded = None;
        for _ in 0..10000 {
            let frame = sender.next_data_frame();
            if chaos.should_drop(frame.frame_type) {
                continue;
            }
            decoded = receiver
                .ingest_data_packet(&frame.payload)
                .expect("ingest data");
            if decoded.is_some() {
                break;
            }
        }

        let recovered = decoded.expect("recovered payload under packet loss");
        assert_eq!(recovered, data);
        assert!(receiver.is_done());
    }

    #[test]
    fn stream_start_frames_are_control_frames() {
        let stream_id = [1u8; VWP_STREAM_ID_LEN];
        let sender = StreamSender::new(stream_id, b"abc", 1300, 0, 2).expect("sender");
        let frames = sender.stream_start_frames(1, 0).expect("frames");
        assert!(!frames.is_empty());
        assert!(frames.iter().all(|f| f.frame_type == VwpFrameType::Control));
        let chunk = ControlChunk::decode(&frames[0].payload).expect("chunk");
        assert_eq!(chunk.message_id, 1);
    }

    #[test]
    fn ping_pong_roundtrip() {
        let sender = NodeId::from_bytes([0x11; 32]);

        let ping = StreamCommand::Ping { sender_id: sender };
        let ping_raw = ping.encode();
        match StreamCommand::decode(&ping_raw).expect("decode ping") {
            StreamCommand::Ping { sender_id } => assert_eq!(sender_id, sender),
            other => panic!("unexpected decoded command: {other:?}"),
        }

        let pong = StreamCommand::Pong { sender_id: sender };
        let pong_raw = pong.encode();
        match StreamCommand::decode(&pong_raw).expect("decode pong") {
            StreamCommand::Pong { sender_id } => assert_eq!(sender_id, sender),
            other => panic!("unexpected decoded command: {other:?}"),
        }
    }

    #[test]
    fn stream_receiver_ignores_dht_commands() {
        let mut receiver = StreamReceiver::default();
        let sender = NodeId::from_bytes([0x22; 32]);

        let ping = StreamCommand::Ping { sender_id: sender }.encode();
        let event = receiver
            .on_control_payload(&ping)
            .expect("ping should decode");
        assert_eq!(event, StreamControlEvent::Ignored);

        let pong = StreamCommand::Pong { sender_id: sender }.encode();
        let event = receiver
            .on_control_payload(&pong)
            .expect("pong should decode");
        assert_eq!(event, StreamControlEvent::Ignored);

        let find = StreamCommand::FindNode { target_id: sender }.encode();
        let event = receiver
            .on_control_payload(&find)
            .expect("find should decode");
        assert_eq!(event, StreamControlEvent::Ignored);

        let nodes = StreamCommand::NodesFound {
            nodes: vec![sender],
        }
        .encode();
        let event = receiver
            .on_control_payload(&nodes)
            .expect("nodes_found should decode");
        assert_eq!(event, StreamControlEvent::Ignored);

        let key = ContentKey::from_bytes([0x33; 32]);
        let store = StreamCommand::StoreProvider {
            key,
            provider_id: sender,
        }
        .encode();
        let event = receiver
            .on_control_payload(&store)
            .expect("store_provider should decode");
        assert_eq!(event, StreamControlEvent::Ignored);

        let find_value = StreamCommand::FindValue { key }.encode();
        let event = receiver
            .on_control_payload(&find_value)
            .expect("find_value should decode");
        assert_eq!(event, StreamControlEvent::Ignored);

        let value_found = StreamCommand::ValueFound {
            key,
            providers: vec![sender],
        }
        .encode();
        let event = receiver
            .on_control_payload(&value_found)
            .expect("value_found should decode");
        assert_eq!(event, StreamControlEvent::Ignored);
    }

    #[test]
    fn find_node_and_nodes_found_roundtrip() {
        let mut target = [0u8; 32];
        target[0] = 0xAB;
        let target = NodeId::from_bytes(target);

        let find = StreamCommand::FindNode { target_id: target };
        let find_raw = find.encode();
        match StreamCommand::decode(&find_raw).expect("decode find") {
            StreamCommand::FindNode { target_id } => assert_eq!(target_id, target),
            other => panic!("unexpected decoded command: {other:?}"),
        }

        let n1 = NodeId::from_bytes([0x11; 32]);
        let n2 = NodeId::from_bytes([0x22; 32]);
        let found = StreamCommand::NodesFound {
            nodes: vec![n1, n2],
        };
        let found_raw = found.encode();
        match StreamCommand::decode(&found_raw).expect("decode nodes_found") {
            StreamCommand::NodesFound { nodes } => assert_eq!(nodes, vec![n1, n2]),
            other => panic!("unexpected decoded command: {other:?}"),
        }
    }

    #[test]
    fn store_provider_and_find_value_roundtrip() {
        let key = ContentKey::from_bytes([0xAB; 32]);
        let provider = NodeId::from_bytes([0x42; 32]);

        let store = StreamCommand::StoreProvider {
            key,
            provider_id: provider,
        };
        let store_raw = store.encode();
        match StreamCommand::decode(&store_raw).expect("decode store_provider") {
            StreamCommand::StoreProvider {
                key: decoded_key,
                provider_id,
            } => {
                assert_eq!(decoded_key, key);
                assert_eq!(provider_id, provider);
            }
            other => panic!("unexpected decoded command: {other:?}"),
        }

        let find = StreamCommand::FindValue { key };
        let find_raw = find.encode();
        match StreamCommand::decode(&find_raw).expect("decode find_value") {
            StreamCommand::FindValue { key: decoded_key } => assert_eq!(decoded_key, key),
            other => panic!("unexpected decoded command: {other:?}"),
        }
    }

    #[test]
    fn value_found_roundtrip() {
        let key = ContentKey::from_bytes([0x11; 32]);
        let p1 = NodeId::from_bytes([0xA1; 32]);
        let p2 = NodeId::from_bytes([0xB2; 32]);

        let value = StreamCommand::ValueFound {
            key,
            providers: vec![p1, p2],
        };
        let raw = value.encode();
        match StreamCommand::decode(&raw).expect("decode value_found") {
            StreamCommand::ValueFound {
                key: decoded_key,
                providers,
            } => {
                assert_eq!(decoded_key, key);
                assert_eq!(providers, vec![p1, p2]);
            }
            other => panic!("unexpected decoded command: {other:?}"),
        }
    }

    #[test]
    fn nodes_found_rejects_invalid_length() {
        let malformed = vec![CMD_DHT_NODES_FOUND, 2, 0xAA];
        assert!(StreamCommand::decode(&malformed).is_err());
    }

    #[test]
    fn store_provider_rejects_invalid_length() {
        let malformed = vec![CMD_DHT_STORE_PROVIDER, 1, 2, 3];
        assert!(StreamCommand::decode(&malformed).is_err());
    }

    #[test]
    fn value_found_rejects_invalid_length() {
        let malformed = vec![CMD_DHT_VALUE_FOUND, 0xAA];
        assert!(StreamCommand::decode(&malformed).is_err());
    }
}
