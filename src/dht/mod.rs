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

    pub fn insert(&mut self, node_id: NodeId) -> InsertOutcome {
        let Some(bucket_index) = self.bucket_index_for(&node_id) else {
            return InsertOutcome::IgnoredSelf;
        };

        let bucket = &mut self.buckets[bucket_index as usize];
        if let Some(pos) = bucket.nodes.iter().position(|n| *n == node_id) {
            let existing = bucket
                .nodes
                .remove(pos)
                .expect("node index from position must exist");
            bucket.nodes.push_back(existing);
            return InsertOutcome::AlreadyPresent { bucket_index };
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

            return InsertOutcome::PendingPing {
                bucket_index,
                stale_node,
                new_candidate: node_id,
            };
        }

        bucket.nodes.push_back(node_id);
        InsertOutcome::Inserted { bucket_index }
    }

    pub fn mark_active(&mut self, node_id: NodeId) -> bool {
        let Some(bucket_index) = self.bucket_index_for(&node_id) else {
            return false;
        };

        let bucket = &mut self.buckets[bucket_index as usize];
        let Some(pos) = bucket.nodes.iter().position(|n| *n == node_id) else {
            return false;
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

        true
    }

    pub fn replace_stale(&mut self, dead_node: NodeId, new_candidate: NodeId) -> bool {
        let Some(bucket_index) = self.bucket_index_for(&dead_node) else {
            return false;
        };

        if self.bucket_index_for(&new_candidate) != Some(bucket_index) {
            return false;
        }

        let bucket = &mut self.buckets[bucket_index as usize];

        if let Some(pending) = bucket.pending {
            if pending.stale_node == dead_node && pending.new_candidate != new_candidate {
                return false;
            }
        }

        let Some(dead_pos) = bucket.nodes.iter().position(|n| *n == dead_node) else {
            return false;
        };

        bucket.nodes.remove(dead_pos);
        if !bucket.nodes.contains(&new_candidate) {
            bucket.nodes.push_back(new_candidate);
        }

        if let Some(rep_pos) = bucket.replacements.iter().position(|n| *n == new_candidate) {
            bucket.replacements.remove(rep_pos);
        }
        bucket.pending = None;
        true
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

        let outcome = table.insert(overflow_id);
        assert_eq!(
            outcome,
            InsertOutcome::PendingPing {
                bucket_index: 255,
                stale_node: oldest_id,
                new_candidate: overflow_id,
            }
        );
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
}
