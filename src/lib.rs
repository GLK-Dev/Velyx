use anyhow::{Context, Result, bail};
use std::collections::HashMap;

pub mod stream;
pub mod dht;

pub const PROTOCOL_MAGIC: [u8; 4] = *b"VLYX";
pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 28;
pub const REPLAY_WINDOW_SIZE: u64 = 128;
pub const VWP_STREAM_ID_LEN: usize = 32;
pub const VWP_MAX_PAYLOAD: usize = 1400;
pub const VWP_HEADER_LEN: usize = 1 + 4 + VWP_STREAM_ID_LEN;

pub const ERR_UNSUPPORTED_VERSION: u16 = 0x0001;
pub const ERR_MALFORMED_PACKET: u16 = 0x0002;
pub const ERR_UNEXPECTED_PACKET_TYPE: u16 = 0x0003;
pub const ERR_INVALID_SESSION: u16 = 0x0004;
pub const ERR_REPLAY_DETECTED: u16 = 0x0005;
pub const ERR_CAPABILITY_MISMATCH: u16 = 0x0006;

pub const ERR_HANDSHAKE_FAILED: u16 = 0x0101;
pub const ERR_NO_SHARED_VERSION: u16 = 0x0102;
pub const ERR_NEGOTIATION_ECHO_MISMATCH: u16 = 0x0103;

pub const ERR_RATE_LIMITED: u16 = 0x0201;
pub const ERR_INTERNAL: u16 = 0x0202;
pub const ERR_BUSY_RETRY: u16 = 0x0203;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Handshake1 = 1,
    Handshake2 = 2,
    Handshake3 = 3,
    Data = 16,
    Ack = 17,
    Control = 18,
    Keepalive = 19,
    ErrorPacket = 255,
}

impl TryFrom<u8> for PacketType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Handshake1),
            2 => Ok(Self::Handshake2),
            3 => Ok(Self::Handshake3),
            16 => Ok(Self::Data),
            17 => Ok(Self::Ack),
            18 => Ok(Self::Control),
            19 => Ok(Self::Keepalive),
            255 => Ok(Self::ErrorPacket),
            _ => bail!("unknown packet type: {value}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirePacket {
    pub version: u8,
    pub packet_type: PacketType,
    pub flags: u16,
    pub session_id: u64,
    pub seq: u64,
    pub payload: Vec<u8>,
}

impl WirePacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let payload_len: u32 = self
            .payload
            .len()
            .try_into()
            .context("payload too large for wire format")?;

        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&PROTOCOL_MAGIC);
        out.push(self.version);
        out.push(self.packet_type as u8);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            bail!("packet too short: {}", buf.len());
        }
        if buf[0..4] != PROTOCOL_MAGIC {
            bail!("invalid magic");
        }

        let version = buf[4];
        let packet_type = PacketType::try_from(buf[5])?;
        let flags = u16::from_be_bytes([buf[6], buf[7]]);

        let mut sid = [0u8; 8];
        sid.copy_from_slice(&buf[8..16]);
        let session_id = u64::from_be_bytes(sid);

        let mut seq = [0u8; 8];
        seq.copy_from_slice(&buf[16..24]);
        let seq = u64::from_be_bytes(seq);

        let mut len = [0u8; 4];
        len.copy_from_slice(&buf[24..28]);
        let payload_len = u32::from_be_bytes(len) as usize;

        if buf.len() != HEADER_LEN + payload_len {
            bail!(
                "invalid packet length: header says {}, actual {}",
                payload_len,
                buf.len() - HEADER_LEN
            );
        }

        Ok(Self {
            version,
            packet_type,
            flags,
            session_id,
            seq,
            payload: buf[HEADER_LEN..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VwpFrameType {
    Control = 1,
    Data = 2,
    Ack = 3,
}

impl TryFrom<u8> for VwpFrameType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::Data),
            3 => Ok(Self::Ack),
            _ => bail!("unknown VWP frame type: {value}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VwpFrame {
    pub frame_type: VwpFrameType,
    pub seq: u32,
    pub stream_id: [u8; VWP_STREAM_ID_LEN],
    pub payload: Vec<u8>,
}

impl VwpFrame {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.payload.len() > VWP_MAX_PAYLOAD {
            bail!(
                "VWP payload too large: {} > {}",
                self.payload.len(),
                VWP_MAX_PAYLOAD
            );
        }

        let mut out = Vec::with_capacity(VWP_HEADER_LEN + self.payload.len());
        out.push(self.frame_type as u8);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.stream_id);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < VWP_HEADER_LEN {
            bail!("VWP frame too short: {}", input.len());
        }

        let frame_type = VwpFrameType::try_from(input[0])?;
        let seq = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);

        let mut stream_id = [0u8; VWP_STREAM_ID_LEN];
        stream_id.copy_from_slice(&input[5..5 + VWP_STREAM_ID_LEN]);
        let payload = input[VWP_HEADER_LEN..].to_vec();

        if payload.len() > VWP_MAX_PAYLOAD {
            bail!(
                "decoded VWP payload too large: {} > {}",
                payload.len(),
                VWP_MAX_PAYLOAD
            );
        }

        Ok(Self {
            frame_type,
            seq,
            stream_id,
            payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlChunk {
    pub message_id: u32,
    pub chunk_index: u16,
    pub total_chunks: u16,
    pub payload: Vec<u8>,
}

impl ControlChunk {
    pub const HEADER_LEN: usize = 8;

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.chunk_index >= self.total_chunks {
            bail!(
                "invalid control chunk index {} for total {}",
                self.chunk_index,
                self.total_chunks
            );
        }

        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.chunk_index.to_be_bytes());
        out.extend_from_slice(&self.total_chunks.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < Self::HEADER_LEN {
            bail!("control chunk too short: {}", input.len());
        }

        let message_id = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        let chunk_index = u16::from_be_bytes([input[4], input[5]]);
        let total_chunks = u16::from_be_bytes([input[6], input[7]]);
        if total_chunks == 0 {
            bail!("invalid total_chunks=0");
        }
        if chunk_index >= total_chunks {
            bail!(
                "invalid chunk index {} for total {}",
                chunk_index,
                total_chunks
            );
        }

        Ok(Self {
            message_id,
            chunk_index,
            total_chunks,
            payload: input[Self::HEADER_LEN..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlAck {
    pub message_id: u32,
    pub chunk_index: u16,
}

impl ControlAck {
    pub const LEN: usize = 6;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..4].copy_from_slice(&self.message_id.to_be_bytes());
        out[4..6].copy_from_slice(&self.chunk_index.to_be_bytes());
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != Self::LEN {
            bail!("invalid control ack length: {}", input.len());
        }
        Ok(Self {
            message_id: u32::from_be_bytes([input[0], input[1], input[2], input[3]]),
            chunk_index: u16::from_be_bytes([input[4], input[5]]),
        })
    }
}

pub fn chunk_control_message(
    stream_id: [u8; VWP_STREAM_ID_LEN],
    message_id: u32,
    start_seq: u32,
    message: &[u8],
) -> Result<Vec<VwpFrame>> {
    let max_chunk_payload = VWP_MAX_PAYLOAD
        .checked_sub(ControlChunk::HEADER_LEN)
        .context("invalid VWP max payload")?;
    if max_chunk_payload == 0 {
        bail!("max control chunk payload is zero");
    }

    let total_chunks_usize = message.len().div_ceil(max_chunk_payload).max(1);
    let total_chunks: u16 = total_chunks_usize
        .try_into()
        .context("control message too large (too many chunks)")?;

    let mut frames = Vec::with_capacity(total_chunks_usize);
    for i in 0..total_chunks_usize {
        let start = i * max_chunk_payload;
        let end = ((i + 1) * max_chunk_payload).min(message.len());
        let chunk = ControlChunk {
            message_id,
            chunk_index: i as u16,
            total_chunks,
            payload: message[start..end].to_vec(),
        };
        frames.push(VwpFrame {
            frame_type: VwpFrameType::Control,
            seq: start_seq.wrapping_add(i as u32),
            stream_id,
            payload: chunk.encode()?,
        });
    }

    Ok(frames)
}

#[derive(Debug, Default)]
pub struct ControlAssembler {
    in_flight: HashMap<u32, Vec<Option<Vec<u8>>>>,
}

impl ControlAssembler {
    pub fn push_chunk(&mut self, chunk: ControlChunk) -> Result<Option<Vec<u8>>> {
        let slots = self
            .in_flight
            .entry(chunk.message_id)
            .or_insert_with(|| vec![None; chunk.total_chunks as usize]);

        if slots.len() != chunk.total_chunks as usize {
            bail!(
                "control chunk total mismatch for message {}: existing {}, got {}",
                chunk.message_id,
                slots.len(),
                chunk.total_chunks
            );
        }

        slots[chunk.chunk_index as usize] = Some(chunk.payload);

        if slots.iter().all(Option::is_some) {
            let completed = self
                .in_flight
                .remove(&chunk.message_id)
                .context("missing completed message after assembly")?;
            let mut out = Vec::new();
            for part in completed {
                out.extend_from_slice(part.as_ref().context("assembler missing part")?);
            }
            return Ok(Some(out));
        }

        Ok(None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckFrame {
    pub acked_seq: u64,
    pub ack_bits: u64,
}

impl AckFrame {
    pub const LEN: usize = 16;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..8].copy_from_slice(&self.acked_seq.to_be_bytes());
        out[8..16].copy_from_slice(&self.ack_bits.to_be_bytes());
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != Self::LEN {
            bail!("invalid ack frame length: {}", input.len());
        }

        let mut acked_seq = [0u8; 8];
        acked_seq.copy_from_slice(&input[0..8]);
        let mut ack_bits = [0u8; 8];
        ack_bits.copy_from_slice(&input[8..16]);

        Ok(Self {
            acked_seq: u64::from_be_bytes(acked_seq),
            ack_bits: u64::from_be_bytes(ack_bits),
        })
    }

    pub fn acknowledges(&self, seq: u64) -> bool {
        if seq == self.acked_seq {
            return true;
        }
        if seq > self.acked_seq {
            return false;
        }

        let delta = self.acked_seq - seq;
        if delta == 0 || delta > 64 {
            return false;
        }

        let bit_index = delta - 1;
        (self.ack_bits & (1u64 << bit_index)) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorFrame {
    pub code: u16,
    pub detail: String,
}

impl ErrorFrame {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let detail_bytes = self.detail.as_bytes();
        let detail_len: u16 = detail_bytes
            .len()
            .try_into()
            .context("error detail too long")?;

        let mut out = Vec::with_capacity(4 + detail_bytes.len());
        out.extend_from_slice(&self.code.to_be_bytes());
        out.extend_from_slice(&detail_len.to_be_bytes());
        out.extend_from_slice(detail_bytes);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < 4 {
            bail!("invalid error frame length: {}", input.len());
        }

        let code = u16::from_be_bytes([input[0], input[1]]);
        let detail_len = u16::from_be_bytes([input[2], input[3]]) as usize;
        if input.len() != 4 + detail_len {
            bail!(
                "invalid error detail length: declared {}, actual {}",
                detail_len,
                input.len().saturating_sub(4)
            );
        }

        let detail = std::str::from_utf8(&input[4..])
            .context("error detail is not valid UTF-8")?
            .to_owned();

        Ok(Self { code, detail })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    highest_seen: Option<u64>,
    bitmap: u128,
}

impl ReplayWindow {
    pub fn check_and_record(&mut self, seq: u64) -> Result<()> {
        match self.highest_seen {
            None => {
                self.highest_seen = Some(seq);
                self.bitmap = 1;
                Ok(())
            }
            Some(highest) => {
                if seq > highest {
                    let delta = seq - highest;
                    if delta >= REPLAY_WINDOW_SIZE {
                        self.bitmap = 1;
                    } else {
                        self.bitmap <<= delta;
                        self.bitmap |= 1;
                    }
                    self.highest_seen = Some(seq);
                    return Ok(());
                }

                let behind = highest - seq;
                if behind >= REPLAY_WINDOW_SIZE {
                    bail!("replay/out-of-window packet: seq={seq}, highest={highest}");
                }

                let mask = 1u128 << behind;
                if self.bitmap & mask != 0 {
                    bail!("duplicate packet sequence: {seq}");
                }

                self.bitmap |= mask;
                Ok(())
            }
        }
    }
}

pub type CapabilityMask = u64;
pub const CAP_FEC_V1: CapabilityMask = 1 << 0;
pub const CAP_DHT_V1: CapabilityMask = 1 << 1;
pub const CAP_OBFS_V1: CapabilityMask = 1 << 2;
pub const CAP_RELAY_V1: CapabilityMask = 1 << 3;

#[derive(Debug, Clone, Copy)]
pub struct CapabilitySet {
    pub min_version: u8,
    pub max_version: u8,
    pub mask: CapabilityMask,
}

impl CapabilitySet {
    pub fn mvp_default() -> Self {
        Self {
            min_version: 1,
            max_version: 1,
            mask: CAP_FEC_V1 | CAP_DHT_V1 | CAP_OBFS_V1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello {
    pub min_version: u8,
    pub max_version: u8,
    pub caps: CapabilityMask,
}

impl ClientHello {
    pub const LEN: usize = 10;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = self.min_version;
        out[1] = self.max_version;
        out[2..10].copy_from_slice(&self.caps.to_be_bytes());
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != Self::LEN {
            bail!("invalid client hello length: {}", input.len());
        }
        let mut caps = [0u8; 8];
        caps.copy_from_slice(&input[2..10]);
        Ok(Self {
            min_version: input[0],
            max_version: input[1],
            caps: u64::from_be_bytes(caps),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    pub min_version: u8,
    pub max_version: u8,
    pub caps: CapabilityMask,
    pub selected_version: u8,
    pub selected_caps: CapabilityMask,
}

impl ServerHello {
    pub const LEN: usize = 19;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = self.min_version;
        out[1] = self.max_version;
        out[2..10].copy_from_slice(&self.caps.to_be_bytes());
        out[10] = self.selected_version;
        out[11..19].copy_from_slice(&self.selected_caps.to_be_bytes());
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != Self::LEN {
            bail!("invalid server hello length: {}", input.len());
        }
        let mut caps = [0u8; 8];
        caps.copy_from_slice(&input[2..10]);

        let mut selected_caps = [0u8; 8];
        selected_caps.copy_from_slice(&input[11..19]);

        Ok(Self {
            min_version: input[0],
            max_version: input[1],
            caps: u64::from_be_bytes(caps),
            selected_version: input[10],
            selected_caps: u64::from_be_bytes(selected_caps),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientFinish {
    pub selected_version: u8,
    pub selected_caps: CapabilityMask,
}

impl ClientFinish {
    pub const LEN: usize = 9;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = self.selected_version;
        out[1..9].copy_from_slice(&self.selected_caps.to_be_bytes());
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != Self::LEN {
            bail!("invalid client finish length: {}", input.len());
        }
        let mut caps = [0u8; 8];
        caps.copy_from_slice(&input[1..9]);
        Ok(Self {
            selected_version: input[0],
            selected_caps: u64::from_be_bytes(caps),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    pub version: u8,
    pub caps: CapabilityMask,
}

pub fn negotiate(local: CapabilitySet, remote: ClientHello) -> Result<Negotiated> {
    if local.min_version > local.max_version {
        bail!("local version bounds invalid");
    }
    if remote.min_version > remote.max_version {
        bail!("remote version bounds invalid");
    }

    let min = local.min_version.max(remote.min_version);
    let max = local.max_version.min(remote.max_version);
    if min > max {
        bail!(
            "no shared protocol version: local {}-{}, remote {}-{}",
            local.min_version,
            local.max_version,
            remote.min_version,
            remote.max_version
        );
    }

    Ok(Negotiated {
        version: max,
        caps: local.mask & remote.caps,
    })
}

pub fn parse_server_and_validate(local: CapabilitySet, server: ServerHello) -> Result<Negotiated> {
    let server_as_client = ClientHello {
        min_version: server.min_version,
        max_version: server.max_version,
        caps: server.caps,
    };

    let expected = negotiate(local, server_as_client)?;
    if expected.version != server.selected_version {
        bail!(
            "server selected invalid version: got {}, expected {}",
            server.selected_version,
            expected.version
        );
    }
    if expected.caps != server.selected_caps {
        bail!(
            "server selected invalid capabilities: got {:#x}, expected {:#x}",
            server.selected_caps,
            expected.caps
        );
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_rejects_duplicate_and_old() {
        let mut rw = ReplayWindow::default();
        rw.check_and_record(10).expect("first seq accepted");
        rw.check_and_record(11).expect("next seq accepted");
        rw.check_and_record(200).expect("forward jump accepted");
        assert!(rw.check_and_record(11).is_err());
        assert!(rw.check_and_record(0).is_err());
    }

    #[test]
    fn wire_packet_roundtrip() {
        let p = WirePacket {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Data,
            flags: 0,
            session_id: 0x1122334455667788,
            seq: 42,
            payload: b"abc".to_vec(),
        };

        let encoded = p.encode().expect("encode packet");
        let decoded = WirePacket::decode(&encoded).expect("decode packet");
        assert_eq!(p, decoded);
    }

    #[test]
    fn ack_frame_roundtrip_and_lookup() {
        let ack = AckFrame {
            acked_seq: 100,
            ack_bits: 0b1001,
        };

        let encoded = ack.encode();
        let decoded = AckFrame::decode(&encoded).expect("decode ack frame");
        assert_eq!(decoded, ack);
        assert!(decoded.acknowledges(100));
        assert!(decoded.acknowledges(99));
        assert!(decoded.acknowledges(96));
        assert!(!decoded.acknowledges(98));
    }

    #[test]
    fn error_frame_roundtrip() {
        let err = ErrorFrame {
            code: ERR_REPLAY_DETECTED,
            detail: "replay".to_string(),
        };

        let encoded = err.encode().expect("encode error frame");
        let decoded = ErrorFrame::decode(&encoded).expect("decode error frame");
        assert_eq!(decoded, err);
    }

    #[test]
    fn vwp_frame_roundtrip() {
        let mut stream_id = [0u8; VWP_STREAM_ID_LEN];
        stream_id[0] = 1;
        let frame = VwpFrame {
            frame_type: VwpFrameType::Data,
            seq: 77,
            stream_id,
            payload: b"hello-vwp".to_vec(),
        };

        let encoded = frame.encode().expect("encode vwp frame");
        let decoded = VwpFrame::decode(&encoded).expect("decode vwp frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn control_chunk_and_assembly_roundtrip() {
        let mut stream_id = [0u8; VWP_STREAM_ID_LEN];
        stream_id[1] = 2;
        let payload = vec![42u8; 5000];
        let frames = chunk_control_message(stream_id, 99, 0, &payload).expect("chunk message");
        assert!(frames.len() > 1);

        let mut assembler = ControlAssembler::default();
        let mut assembled = None;
        for frame in frames {
            let chunk = ControlChunk::decode(&frame.payload).expect("decode chunk");
            assembled = assembler.push_chunk(chunk).expect("push chunk").or(assembled);
        }

        assert_eq!(assembled.expect("assembled payload"), payload);
    }
}
