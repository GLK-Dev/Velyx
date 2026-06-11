use anyhow::{Context, Result};
use snow::TransportState;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use velyx::{
    PROTOCOL_VERSION, PacketType, VWP_STREAM_ID_LEN, WirePacket, chunk_control_message,
    dht::{NodeId, RoutingAction},
    stream::StreamCommand,
};

pub fn route_action_to_command(action: RoutingAction, local_id: NodeId) -> (NodeId, StreamCommand) {
    match action {
        RoutingAction::Ping(target_id) => (
            target_id,
            StreamCommand::Ping {
                sender_id: local_id,
            },
        ),
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
