use anyhow::{Context, Result};
use snow::TransportState;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use crate::{
    PROTOCOL_VERSION, PacketType, VWP_STREAM_ID_LEN, WirePacket, chunk_control_message,
    dht::{NodeId, RoutingAction, RoutingTable},
    stream::StreamCommand,
};

#[derive(Debug, Clone)]
pub struct ExecutedDhtAction {
    pub route_to: Option<NodeId>,
    pub command: StreamCommand,
}

pub fn execute_dht_action(action: RoutingAction, local_id: NodeId) -> Option<ExecutedDhtAction> {
    match action {
        RoutingAction::Ping(target_id) => Some(ExecutedDhtAction {
            route_to: Some(target_id),
            command: StreamCommand::Ping {
                sender_id: local_id,
            },
        }),
        RoutingAction::Lookup(target_id) => Some(ExecutedDhtAction {
            route_to: None,
            command: StreamCommand::FindNode { target_id },
        }),
    }
}

pub fn refresh_bucket_lookup_action(
    table: &RoutingTable,
    bucket_index: u8,
    entropy: u64,
) -> RoutingAction {
    let mut target = *table.local_id().as_bytes();

    // Keep all higher bits equal to local_id and flip the bucket bit.
    let current = get_bit_lsb(&target, bucket_index as usize);
    set_bit_lsb(&mut target, bucket_index as usize, !current);

    // Randomize lower-order bits to probe different points in this bucket range.
    let mut state = entropy ^ 0x9E37_79B9_7F4A_7C15u64;
    for bit in 0..bucket_index as usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        set_bit_lsb(&mut target, bit, (state & 1) != 0);
    }

    RoutingAction::Lookup(NodeId::from_bytes(target))
}

fn get_bit_lsb(bytes: &[u8; 32], bit_index: usize) -> bool {
    let byte_from_end = bit_index / 8;
    let bit_in_byte = bit_index % 8;
    let byte_index = 31 - byte_from_end;
    (bytes[byte_index] & (1u8 << bit_in_byte)) != 0
}

fn set_bit_lsb(bytes: &mut [u8; 32], bit_index: usize, value: bool) {
    let byte_from_end = bit_index / 8;
    let bit_in_byte = bit_index % 8;
    let byte_index = 31 - byte_from_end;
    let mask = 1u8 << bit_in_byte;

    if value {
        bytes[byte_index] |= mask;
    } else {
        bytes[byte_index] &= !mask;
    }
}

pub async fn send_control_command(
    socket: &UdpSocket,
    transport: &mut TransportState,
    out_buf: &mut [u8],
    session_id: u64,
    tx_seq: &mut u64,
    vwp_tx_seq: &mut u32,
    stream_id: [u8; VWP_STREAM_ID_LEN],
    message_id: u32,
    remote: SocketAddr,
    command: StreamCommand,
) -> Result<()> {
    let payload = command.encode();
    let frames = chunk_control_message(stream_id, message_id, *vwp_tx_seq, &payload)
        .context("chunk control command payload")?;

    for frame in &frames {
        let frame_raw = frame.encode().context("encode control command frame")?;
        let encrypted_len = transport
            .write_message(&frame_raw, out_buf)
            .context("encrypt control command frame")?;

        let pkt = WirePacket {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Data,
            flags: 0,
            session_id,
            seq: *tx_seq,
            payload: out_buf[..encrypted_len].to_vec(),
        };

        let raw = pkt.encode().context("encode control command packet")?;
        socket
            .send_to(&raw, remote)
            .await
            .with_context(|| format!("send control command to {remote}"))?;

        *tx_seq = tx_seq.wrapping_add(1);
    }

    *vwp_tx_seq = vwp_tx_seq.wrapping_add(frames.len() as u32);

    Ok(())
}
