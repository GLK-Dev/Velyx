use serde::Deserialize;
use velyx::{
    AckFrame, CAP_DHT_V1, CAP_FEC_V1, CAP_OBFS_V1, CapabilitySet, ClientFinish, ClientHello,
    ERR_REPLAY_DETECTED, ErrorFrame, PacketType, ServerHello, WirePacket, negotiate,
    parse_server_and_validate,
};

#[derive(Debug, Deserialize)]
struct WireVectors {
    wire_packets: Vec<WirePacketVector>,
    capability_vectors: CapabilityVectors,
    control_vectors: ControlVectors,
}

#[derive(Debug, Deserialize)]
struct WirePacketVector {
    name: String,
    hex: String,
    version: u8,
    packet_type: u8,
    flags: u16,
    session_id: u64,
    seq: u64,
    payload_hex: String,
}

#[derive(Debug, Deserialize)]
struct CapabilityVectors {
    client_hello_hex: String,
    server_hello_hex: String,
    client_finish_hex: String,
}

#[derive(Debug, Deserialize)]
struct ControlVectors {
    ack_hex: String,
    error_hex: String,
}

#[test]
fn wire_vectors_are_stable() {
    let raw = std::fs::read_to_string("test_vectors/wire_vectors.json").expect("read vectors");
    let vectors: WireVectors = serde_json::from_str(&raw).expect("parse vectors");

    for v in &vectors.wire_packets {
        let bytes = hex::decode(&v.hex).expect("decode packet hex");
        let packet = WirePacket::decode(&bytes).expect("decode wire packet");

        assert_eq!(packet.version, v.version, "vector {} version", v.name);
        assert_eq!(packet.packet_type as u8, v.packet_type, "vector {} type", v.name);
        assert_eq!(packet.flags, v.flags, "vector {} flags", v.name);
        assert_eq!(packet.session_id, v.session_id, "vector {} session", v.name);
        assert_eq!(packet.seq, v.seq, "vector {} seq", v.name);
        assert_eq!(hex::encode(&packet.payload), v.payload_hex, "vector {} payload", v.name);

        let reencoded = packet.encode().expect("re-encode packet");
        assert_eq!(hex::encode(reencoded), v.hex, "vector {} re-encode", v.name);
    }
}

#[test]
fn capability_vectors_are_stable() {
    let raw = std::fs::read_to_string("test_vectors/wire_vectors.json").expect("read vectors");
    let vectors: WireVectors = serde_json::from_str(&raw).expect("parse vectors");

    let ch = ClientHello {
        min_version: 1,
        max_version: 1,
        caps: CAP_FEC_V1 | CAP_DHT_V1 | CAP_OBFS_V1 | (1 << 3),
    };
    assert_eq!(hex::encode(ch.encode()), vectors.capability_vectors.client_hello_hex);

    let sh = ServerHello {
        min_version: 1,
        max_version: 1,
        caps: CAP_FEC_V1 | CAP_OBFS_V1 | (1 << 3),
        selected_version: 1,
        selected_caps: CAP_FEC_V1 | CAP_OBFS_V1,
    };
    assert_eq!(hex::encode(sh.encode()), vectors.capability_vectors.server_hello_hex);

    let cf = ClientFinish {
        selected_version: 1,
        selected_caps: CAP_FEC_V1 | CAP_OBFS_V1,
    };
    assert_eq!(hex::encode(cf.encode()), vectors.capability_vectors.client_finish_hex);
}

#[test]
fn negotiation_interop_path() {
    let initiator = CapabilitySet {
        min_version: 1,
        max_version: 2,
        mask: CAP_FEC_V1 | CAP_DHT_V1 | CAP_OBFS_V1,
    };

    let responder_hello = ClientHello {
        min_version: 1,
        max_version: 1,
        caps: CAP_FEC_V1 | CAP_OBFS_V1,
    };

    let negotiated = negotiate(initiator, responder_hello).expect("negotiate");
    assert_eq!(negotiated.version, 1);
    assert_eq!(negotiated.caps, CAP_FEC_V1 | CAP_OBFS_V1);

    let server = ServerHello {
        min_version: 1,
        max_version: 1,
        caps: CAP_FEC_V1 | CAP_OBFS_V1,
        selected_version: negotiated.version,
        selected_caps: negotiated.caps,
    };

    let validated = parse_server_and_validate(initiator, server).expect("validate server hello");
    assert_eq!(validated.version, 1);
    assert_eq!(validated.caps, CAP_FEC_V1 | CAP_OBFS_V1);

    let packet = WirePacket {
        version: 1,
        packet_type: PacketType::Data,
        flags: 0,
        session_id: 42,
        seq: 7,
        payload: b"interop".to_vec(),
    };

    let decoded = WirePacket::decode(&packet.encode().expect("encode")).expect("decode");
    assert_eq!(decoded.payload, b"interop");
}

#[test]
fn control_vectors_are_stable() {
    let raw = std::fs::read_to_string("test_vectors/wire_vectors.json").expect("read vectors");
    let vectors: WireVectors = serde_json::from_str(&raw).expect("parse vectors");

    let ack = AckFrame {
        acked_seq: 100,
        ack_bits: 0b1001,
    };
    assert_eq!(hex::encode(ack.encode()), vectors.control_vectors.ack_hex);

    let err = ErrorFrame {
        code: ERR_REPLAY_DETECTED,
        detail: "replay".to_string(),
    };
    assert_eq!(
        hex::encode(err.encode().expect("encode error")),
        vectors.control_vectors.error_hex
    );

    let decoded_ack = AckFrame::decode(&hex::decode(&vectors.control_vectors.ack_hex).expect("ack hex"))
        .expect("decode ack");
    assert!(decoded_ack.acknowledges(100));
    assert!(decoded_ack.acknowledges(99));
    assert!(decoded_ack.acknowledges(96));
    assert!(!decoded_ack.acknowledges(98));

    let decoded_error = ErrorFrame::decode(
        &hex::decode(&vectors.control_vectors.error_hex).expect("error hex"),
    )
    .expect("decode error");
    assert_eq!(decoded_error.code, ERR_REPLAY_DETECTED);
    assert_eq!(decoded_error.detail, "replay");
}
