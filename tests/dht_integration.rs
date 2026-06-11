use velyx::dht::{InsertOutcome, NodeId, RoutingAction, RoutingTable};
use velyx::dht_bridge::execute_dht_action;
use velyx::stream::StreamCommand;

fn table_contains(table: &RoutingTable, node: NodeId) -> bool {
    let Some(bucket_index) = table.bucket_index_for(&node) else {
        return false;
    };
    table.bucket_nodes(bucket_index).contains(&node)
}

#[test]
fn dht_action_to_ping_pong_roundtrip_updates_both_tables() {
    let id_a = NodeId::from_bytes([0u8; 32]);

    let mut b_raw = [0u8; 32];
    b_raw[0] = 0x80;
    b_raw[31] = 0x01;
    let id_b = NodeId::from_bytes(b_raw);

    let mut c_raw = [0u8; 32];
    c_raw[0] = 0x80;
    c_raw[31] = 0x02;
    let id_c = NodeId::from_bytes(c_raw);

    let mut table_a = RoutingTable::new(id_a, 1);
    let mut table_b = RoutingTable::new(id_b, 20);

    let first_insert = table_a.insert_with_actions(id_b);
    assert_eq!(first_insert.value, InsertOutcome::Inserted { bucket_index: 255 });
    assert!(first_insert.actions.is_empty());

    let second_insert = table_a.insert_with_actions(id_c);
    assert_eq!(
        second_insert.value,
        InsertOutcome::PendingPing {
            bucket_index: 255,
            stale_node: id_b,
            new_candidate: id_c,
        }
    );
    assert_eq!(second_insert.actions, vec![RoutingAction::Ping(id_b)]);

    let outbound = execute_dht_action(second_insert.actions[0], table_a.local_id())
        .expect("action should convert to outbound command");
    assert_eq!(outbound.route_to, Some(id_b));

    let wire_ping = outbound.command.encode();
    let decoded_ping = StreamCommand::decode(&wire_ping).expect("decode ping");
    let ping_sender = match decoded_ping {
        StreamCommand::Ping { sender_id } => sender_id,
        other => panic!("expected ping command, got {other:?}"),
    };
    assert_eq!(ping_sender, id_a);

    let insert_on_b = table_b.insert_with_actions(ping_sender);
    assert_eq!(insert_on_b.value, InsertOutcome::Inserted { bucket_index: 255 });

    let pong = StreamCommand::Pong {
        sender_id: table_b.local_id(),
    };
    let wire_pong = pong.encode();
    let decoded_pong = StreamCommand::decode(&wire_pong).expect("decode pong");
    let pong_sender = match decoded_pong {
        StreamCommand::Pong { sender_id } => sender_id,
        other => panic!("expected pong command, got {other:?}"),
    };
    assert_eq!(pong_sender, id_b);

    let mark_on_a = table_a.mark_active_with_actions(pong_sender);
    assert!(mark_on_a.value);

    assert!(table_contains(&table_a, id_b));
    assert!(table_contains(&table_b, id_a));
}
