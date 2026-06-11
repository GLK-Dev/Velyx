use std::collections::VecDeque;

pub const NODE_ID_LEN: usize = 32;
pub const K_BUCKET_COUNT: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId([u8; NODE_ID_LEN]);

impl NodeId {
    pub const fn from_bytes(bytes: [u8; NODE_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; NODE_ID_LEN] {
        &self.0
    }

    pub fn xor_distance(&self, other: &Self) -> XorDistance {
        let mut out = [0u8; NODE_ID_LEN];
        let mut i = 0;
        while i < NODE_ID_LEN {
            out[i] = self.0[i] ^ other.0[i];
            i += 1;
        }
        XorDistance(out)
    }

    pub fn bucket_index(&self, other: &Self) -> Option<u8> {
        self.xor_distance(other).bucket_index()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XorDistance([u8; NODE_ID_LEN]);

impl XorDistance {
    pub const fn as_bytes(&self) -> &[u8; NODE_ID_LEN] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    pub fn bucket_index(&self) -> Option<u8> {
        for (i, byte) in self.0.iter().copied().enumerate() {
            if byte != 0 {
                let leading = byte.leading_zeros() as usize;
                let bit_from_msb = i * 8 + leading;
                let index = 255usize - bit_from_msb;
                return Some(index as u8);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted { bucket_index: u8 },
    AlreadyPresent { bucket_index: u8 },
    PendingPing {
        bucket_index: u8,
        stale_node: NodeId,
        new_candidate: NodeId,
    },
    IgnoredSelf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingAction {
    Ping(NodeId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingResult<T> {
    pub value: T,
    pub actions: Vec<RoutingAction>,
}

#[derive(Debug, Clone)]
struct Bucket {
    nodes: VecDeque<NodeId>,
    replacements: VecDeque<NodeId>,
    pending: Option<PendingReplacement>,
}

impl Bucket {
    fn new(k: usize) -> Self {
        Self {
            nodes: VecDeque::with_capacity(k),
            replacements: VecDeque::with_capacity(k),
            pending: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingReplacement {
    stale_node: NodeId,
    new_candidate: NodeId,
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    local_id: NodeId,
    k: usize,
    buckets: Vec<Bucket>,
}

impl RoutingTable {
    pub fn new(local_id: NodeId, k: usize) -> Self {
        assert!(k > 0, "k must be > 0");

        let mut buckets = Vec::with_capacity(K_BUCKET_COUNT);
        for _ in 0..K_BUCKET_COUNT {
            buckets.push(Bucket::new(k));
        }

        Self {
            local_id,
            k,
            buckets,
        }
    }

    pub const fn local_id(&self) -> NodeId {
        self.local_id
    }

    pub const fn k(&self) -> usize {
        self.k
    }

    pub fn bucket_index_for(&self, node_id: &NodeId) -> Option<u8> {
        self.local_id.bucket_index(node_id)
    }

    pub fn insert_with_actions(&mut self, node_id: NodeId) -> RoutingResult<InsertOutcome> {
        let Some(bucket_index) = self.bucket_index_for(&node_id) else {
            return RoutingResult {
                value: InsertOutcome::IgnoredSelf,
                actions: Vec::new(),
            };
        };

        let bucket = &mut self.buckets[bucket_index as usize];
        if let Some(pos) = bucket.nodes.iter().position(|n| *n == node_id) {
            let existing = bucket
                .nodes
                .remove(pos)
                .expect("node index from position must exist");
            bucket.nodes.push_back(existing);
            return RoutingResult {
                value: InsertOutcome::AlreadyPresent { bucket_index },
                actions: Vec::new(),
            };
        }

        if bucket.nodes.len() >= self.k {
            if !bucket.replacements.contains(&node_id) {
                if bucket.replacements.len() >= self.k {
                    bucket.replacements.pop_front();
                }
                bucket.replacements.push_back(node_id);
            }

            let stale_node = *bucket
                .nodes
                .front()
                .expect("full bucket must have oldest entry");
            bucket.pending = Some(PendingReplacement {
                stale_node,
                new_candidate: node_id,
            });

            return RoutingResult {
                value: InsertOutcome::PendingPing {
                    bucket_index,
                    stale_node,
                    new_candidate: node_id,
                },
                actions: vec![RoutingAction::Ping(stale_node)],
            };
        }

        bucket.nodes.push_back(node_id);
        RoutingResult {
            value: InsertOutcome::Inserted { bucket_index },
            actions: Vec::new(),
        }
    }

    pub fn insert(&mut self, node_id: NodeId) -> InsertOutcome {
        self.insert_with_actions(node_id).value
    }

    pub fn mark_active_with_actions(&mut self, node_id: NodeId) -> RoutingResult<bool> {
        let Some(bucket_index) = self.bucket_index_for(&node_id) else {
            return RoutingResult {
                value: false,
                actions: Vec::new(),
            };
        };

        let bucket = &mut self.buckets[bucket_index as usize];
        let Some(pos) = bucket.nodes.iter().position(|n| *n == node_id) else {
            return RoutingResult {
                value: false,
                actions: Vec::new(),
            };
        };

        let node = bucket
            .nodes
            .remove(pos)
            .expect("node index from position must exist");
        bucket.nodes.push_back(node);

        if let Some(pending) = bucket.pending {
            if pending.stale_node == node_id {
                if let Some(rep_pos) = bucket
                    .replacements
                    .iter()
                    .position(|n| *n == pending.new_candidate)
                {
                    bucket.replacements.remove(rep_pos);
                }
                bucket.pending = None;
            }
        }

        RoutingResult {
            value: true,
            actions: Vec::new(),
        }
    }

    pub fn mark_active(&mut self, node_id: NodeId) -> bool {
        self.mark_active_with_actions(node_id).value
    }

    pub fn replace_stale_with_actions(
        &mut self,
        dead_node: NodeId,
        new_candidate: NodeId,
    ) -> RoutingResult<bool> {
        let Some(bucket_index) = self.bucket_index_for(&dead_node) else {
            return RoutingResult {
                value: false,
                actions: Vec::new(),
            };
        };

        if self.bucket_index_for(&new_candidate) != Some(bucket_index) {
            return RoutingResult {
                value: false,
                actions: Vec::new(),
            };
        }

        let bucket = &mut self.buckets[bucket_index as usize];

        if let Some(pending) = bucket.pending {
            if pending.stale_node == dead_node && pending.new_candidate != new_candidate {
                return RoutingResult {
                    value: false,
                    actions: Vec::new(),
                };
            }
        }

        let Some(dead_pos) = bucket.nodes.iter().position(|n| *n == dead_node) else {
            return RoutingResult {
                value: false,
                actions: Vec::new(),
            };
        };

        bucket.nodes.remove(dead_pos);
        if !bucket.nodes.contains(&new_candidate) {
            bucket.nodes.push_back(new_candidate);
        }

        if let Some(rep_pos) = bucket.replacements.iter().position(|n| *n == new_candidate) {
            bucket.replacements.remove(rep_pos);
        }
        bucket.pending = None;
        RoutingResult {
            value: true,
            actions: Vec::new(),
        }
    }

    pub fn replace_stale(&mut self, dead_node: NodeId, new_candidate: NodeId) -> bool {
        self.replace_stale_with_actions(dead_node, new_candidate)
            .value
    }

    pub fn bucket_len(&self, bucket_index: u8) -> usize {
        self.buckets[bucket_index as usize].nodes.len()
    }

    pub fn bucket_nodes(&self, bucket_index: u8) -> Vec<NodeId> {
        self.buckets[bucket_index as usize]
            .nodes
            .iter()
            .copied()
            .collect()
    }

    pub fn find_closest_nodes(&self, target: NodeId, limit: usize) -> Vec<NodeId> {
        if limit == 0 {
            return Vec::new();
        }

        let mut nodes = self
            .buckets
            .iter()
            .flat_map(|bucket| bucket.nodes.iter().copied())
            .collect::<Vec<_>>();

        nodes.sort_by(|a, b| {
            let da = a.xor_distance(&target);
            let db = b.xor_distance(&target);
            da.cmp(&db).then_with(|| a.cmp(b))
        });
        nodes.truncate(limit);
        nodes
    }

    pub fn lookup(&self, target: NodeId) -> Vec<NodeId> {
        self.find_closest_nodes(target, self.k)
    }

    pub fn nodes_found_received<I>(&mut self, nodes: I) -> Vec<RoutingAction>
    where
        I: IntoIterator<Item = NodeId>,
    {
        let mut actions = Vec::new();
        for node in nodes {
            let result = self.insert_with_actions(node);
            actions.extend(result.actions);
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_with_lsb_bit(bit: usize) -> NodeId {
        assert!(bit < K_BUCKET_COUNT);
        let mut bytes = [0u8; NODE_ID_LEN];
        let byte_from_end = bit / 8;
        let bit_in_byte = bit % 8;
        let byte_index = NODE_ID_LEN - 1 - byte_from_end;
        bytes[byte_index] |= 1u8 << bit_in_byte;
        NodeId::from_bytes(bytes)
    }

    #[test]
    fn xor_distance_is_symmetric() {
        let mut a = [0u8; NODE_ID_LEN];
        let mut b = [0u8; NODE_ID_LEN];
        a[0] = 0x80;
        a[31] = 0x01;
        b[0] = 0x40;
        b[30] = 0xAA;

        let a = NodeId::from_bytes(a);
        let b = NodeId::from_bytes(b);

        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));
    }

    #[test]
    fn bucket_index_maps_entire_256_bit_space() {
        let local = NodeId::from_bytes([0u8; NODE_ID_LEN]);

        for expected_bucket in 0..K_BUCKET_COUNT {
            let other = node_with_lsb_bit(expected_bucket);
            let actual_bucket = local.bucket_index(&other).expect("non-zero distance");
            assert_eq!(actual_bucket as usize, expected_bucket);
        }
    }

    #[test]
    fn bucket_index_is_none_for_identical_node_ids() {
        let id = NodeId::from_bytes([7u8; NODE_ID_LEN]);
        assert_eq!(id.bucket_index(&id), None);
    }

    #[test]
    fn full_bucket_returns_pending_ping_for_oldest_node() {
        let local = NodeId::from_bytes([0u8; NODE_ID_LEN]);
        let mut table = RoutingTable::new(local, 20);

        let mut oldest = [0u8; NODE_ID_LEN];
        oldest[0] = 0x80;
        oldest[31] = 0;
        let oldest_id = NodeId::from_bytes(oldest);

        for i in 0..20u8 {
            let mut bytes = [0u8; NODE_ID_LEN];
            bytes[0] = 0x80;
            bytes[31] = i;
            let id = NodeId::from_bytes(bytes);

            let outcome = table.insert(id);
            assert_eq!(
                outcome,
                InsertOutcome::Inserted {
                    bucket_index: 255
                }
            );
        }

        let mut overflow = [0u8; NODE_ID_LEN];
        overflow[0] = 0x80;
        overflow[31] = 200;
        let overflow_id = NodeId::from_bytes(overflow);

        let result = table.insert_with_actions(overflow_id);
        let outcome = result.value;
        assert_eq!(
            outcome,
            InsertOutcome::PendingPing {
                bucket_index: 255,
                stale_node: oldest_id,
                new_candidate: overflow_id,
            }
        );
        assert_eq!(result.actions, vec![RoutingAction::Ping(oldest_id)]);
        assert_eq!(table.bucket_len(255), 20);
    }

    #[test]
    fn mark_active_moves_node_to_bucket_tail() {
        let local = NodeId::from_bytes([0u8; NODE_ID_LEN]);
        let mut table = RoutingTable::new(local, 3);

        let mut a = [0u8; NODE_ID_LEN];
        a[0] = 0x80;
        a[31] = 1;
        let a = NodeId::from_bytes(a);

        let mut b = [0u8; NODE_ID_LEN];
        b[0] = 0x80;
        b[31] = 2;
        let b = NodeId::from_bytes(b);

        let mut c = [0u8; NODE_ID_LEN];
        c[0] = 0x80;
        c[31] = 3;
        let c = NodeId::from_bytes(c);

        table.insert(a);
        table.insert(b);
        table.insert(c);

        assert_eq!(table.bucket_nodes(255), vec![a, b, c]);
        assert!(table.mark_active(b));
        assert_eq!(table.bucket_nodes(255), vec![a, c, b]);
    }

    #[test]
    fn replace_stale_swaps_dead_with_candidate() {
        let local = NodeId::from_bytes([0u8; NODE_ID_LEN]);
        let mut table = RoutingTable::new(local, 2);

        let mut a = [0u8; NODE_ID_LEN];
        a[0] = 0x80;
        a[31] = 1;
        let a = NodeId::from_bytes(a);

        let mut b = [0u8; NODE_ID_LEN];
        b[0] = 0x80;
        b[31] = 2;
        let b = NodeId::from_bytes(b);

        let mut c = [0u8; NODE_ID_LEN];
        c[0] = 0x80;
        c[31] = 3;
        let c = NodeId::from_bytes(c);

        table.insert(a);
        table.insert(b);

        let outcome = table.insert(c);
        assert_eq!(
            outcome,
            InsertOutcome::PendingPing {
                bucket_index: 255,
                stale_node: a,
                new_candidate: c,
            }
        );

        assert!(table.replace_stale(a, c));
        assert_eq!(table.bucket_nodes(255), vec![b, c]);
    }

    #[test]
    fn insert_with_actions_emits_ping_for_lru_head() {
        let local = NodeId::from_bytes([0u8; NODE_ID_LEN]);
        let mut table = RoutingTable::new(local, 2);

        let mut a = [0u8; NODE_ID_LEN];
        a[0] = 0x80;
        a[31] = 1;
        let a = NodeId::from_bytes(a);

        let mut b = [0u8; NODE_ID_LEN];
        b[0] = 0x80;
        b[31] = 2;
        let b = NodeId::from_bytes(b);

        let mut c = [0u8; NODE_ID_LEN];
        c[0] = 0x80;
        c[31] = 3;
        let c = NodeId::from_bytes(c);

        table.insert(a);
        table.insert(b);

        let result = table.insert_with_actions(c);
        assert_eq!(result.actions, vec![RoutingAction::Ping(a)]);
        assert_eq!(
            result.value,
            InsertOutcome::PendingPing {
                bucket_index: 255,
                stale_node: a,
                new_candidate: c,
            }
        );
    }

    #[test]
    fn find_closest_nodes_returns_sorted_by_xor_distance() {
        let local = NodeId::from_bytes([0u8; NODE_ID_LEN]);
        let mut table = RoutingTable::new(local, 20);

        let mut n1 = [0u8; NODE_ID_LEN];
        n1[31] = 0x01;
        let n1 = NodeId::from_bytes(n1);

        let mut n2 = [0u8; NODE_ID_LEN];
        n2[31] = 0x02;
        let n2 = NodeId::from_bytes(n2);

        let mut n3 = [0u8; NODE_ID_LEN];
        n3[31] = 0x04;
        let n3 = NodeId::from_bytes(n3);

        table.insert(n3);
        table.insert(n1);
        table.insert(n2);

        let target = NodeId::from_bytes([0u8; NODE_ID_LEN]);
        let closest = table.find_closest_nodes(target, 3);
        assert_eq!(closest, vec![n1, n2, n3]);
    }

    #[test]
    fn find_closest_nodes_respects_limit_and_empty_cases() {
        let local = NodeId::from_bytes([0u8; NODE_ID_LEN]);
        let mut table = RoutingTable::new(local, 20);
        let target = NodeId::from_bytes([0u8; NODE_ID_LEN]);

        assert!(table.find_closest_nodes(target, 5).is_empty());
        assert!(table.find_closest_nodes(target, 0).is_empty());

        let mut n1 = [0u8; NODE_ID_LEN];
        n1[31] = 0x01;
        let n1 = NodeId::from_bytes(n1);

        let mut n2 = [0u8; NODE_ID_LEN];
        n2[31] = 0x02;
        let n2 = NodeId::from_bytes(n2);

        let mut n3 = [0u8; NODE_ID_LEN];
        n3[31] = 0x03;
        let n3 = NodeId::from_bytes(n3);

        table.insert(n1);
        table.insert(n2);
        table.insert(n3);

        let limited = table.find_closest_nodes(target, 2);
        assert_eq!(limited.len(), 2);

        let via_lookup = table.lookup(target);
        assert_eq!(via_lookup.len(), 3);
    }

    #[test]
    fn nodes_found_received_collects_cascading_actions() {
        let local = NodeId::from_bytes([0u8; NODE_ID_LEN]);
        let mut table = RoutingTable::new(local, 1);

        let mut a = [0u8; NODE_ID_LEN];
        a[0] = 0x80;
        a[31] = 1;
        let a = NodeId::from_bytes(a);

        let mut b = [0u8; NODE_ID_LEN];
        b[0] = 0x80;
        b[31] = 2;
        let b = NodeId::from_bytes(b);

        table.insert(a);
        let actions = table.nodes_found_received(vec![b]);

        assert_eq!(actions, vec![RoutingAction::Ping(a)]);
    }
}
