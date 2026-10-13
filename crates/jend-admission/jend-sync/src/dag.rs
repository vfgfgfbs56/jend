use std::collections::{BTreeMap, BTreeSet};

use crate::{
    codec::{put_u16, put_u32, put_u64, Reader}, Result, SyncDeviceId, SyncDeviceIdentity,
    SyncDevicePublic, SyncError, SyncObjectId,
};

const NODE_DOMAIN: &[u8] = b"JEND/SYNC-MESSAGE-NODE/V1";
const MAX_PARENTS: usize = 16;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageNode {
    /// Conversation id is inside the outer JESP ciphertext, so the relay does
    /// not learn it. It lets the Vault route decrypted sync nodes efficiently.
    pub conversation_id: [u8; 16],
    /// Causal conversation parents. These are encrypted by the outer sync object,
    /// so the relay cannot reconstruct the graph.
    pub parents: Vec<SyncObjectId>,
    /// Previous node created by the same device. This forms a second per-device
    /// anti-fork chain in addition to the conversation DAG.
    pub author_previous: Option<SyncObjectId>,
    pub author: SyncDeviceId,
    /// DeviceSet epoch in which the author was trusted when this node was created.
    pub trust_epoch: u64,
    pub device_counter: u64,
    pub lamport: u64,
    /// Already-encrypted and device-signed `.jend` record bytes.
    pub jend_record: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedMessageNode {
    pub node: MessageNode,
    pub signature: [u8; 64],
}

impl MessageNode {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.parents.len() > MAX_PARENTS || self.jend_record.len() > MAX_RECORD_BYTES || self.device_counter == 0 {
            return Err(SyncError::Malformed);
        }
        let mut parents = self.parents.clone();
        parents.sort();
        parents.dedup();
        if parents.len() != self.parents.len() || parents != self.parents {
            return Err(SyncError::Malformed);
        }
        if let Some(previous) = self.author_previous {
            if !parents.contains(&previous) {
                return Err(SyncError::InvalidDagClock);
            }
        } else if self.device_counter != 1 {
            return Err(SyncError::InvalidDagClock);
        }

        let mut out = Vec::with_capacity(16 + 2 + parents.len() * 32 + 1 + 32 + 16 + 8 + 8 + 8 + 4 + self.jend_record.len());
        out.extend_from_slice(&self.conversation_id);
        put_u16(&mut out, parents.len() as u16);
        for parent in parents {
            out.extend_from_slice(&parent.0);
        }
        match self.author_previous {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id.0);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.author.0);
        put_u64(&mut out, self.trust_epoch);
        put_u64(&mut out, self.device_counter);
        put_u64(&mut out, self.lamport);
        put_u32(&mut out, self.jend_record.len() as u32);
        out.extend_from_slice(&self.jend_record);
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let conversation_id = r.array()?;
        let parent_count = r.u16()? as usize;
        if parent_count > MAX_PARENTS {
            return Err(SyncError::Malformed);
        }
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            parents.push(SyncObjectId(r.array()?));
        }
        if !parents.windows(2).all(|p| p[0] < p[1]) {
            return Err(SyncError::Malformed);
        }
        let author_previous = match r.u8()? {
            0 => None,
            1 => Some(SyncObjectId(r.array()?)),
            _ => return Err(SyncError::Malformed),
        };
        let author = SyncDeviceId(r.array()?);
        let trust_epoch = r.u64()?;
        let device_counter = r.u64()?;
        let lamport = r.u64()?;
        let record_len = r.u32()? as usize;
        if record_len > MAX_RECORD_BYTES {
            return Err(SyncError::Malformed);
        }
        let jend_record = r.take(record_len)?.to_vec();
        r.finish()?;
        let node = Self {
            conversation_id,
            parents,
            author_previous,
            author,
            trust_epoch,
            device_counter,
            lamport,
            jend_record,
        };
        node.canonical_bytes()?;
        Ok(node)
    }
}

impl SignedMessageNode {
    pub fn sign(node: MessageNode, signer: &SyncDeviceIdentity) -> Result<Self> {
        let public = signer.public_identity();
        if node.author != public.device_id {
            return Err(SyncError::UntrustedDevice);
        }
        let signature = signer.sign(NODE_DOMAIN, &node.canonical_bytes()?);
        Ok(Self { node, signature })
    }

    pub fn verify(&self, signer: &SyncDevicePublic) -> Result<()> {
        if signer.device_id != self.node.author {
            return Err(SyncError::UntrustedDevice);
        }
        signer.verify(NODE_DOMAIN, &self.node.canonical_bytes()?, &self.signature)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let node = self.node.canonical_bytes()?;
        let mut out = Vec::with_capacity(4 + node.len() + 64);
        put_u32(&mut out, node.len() as u32);
        out.extend_from_slice(&node);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let len = r.u32()? as usize;
        let node = MessageNode::from_canonical_bytes(r.take(len)?)?;
        let signature = r.array()?;
        r.finish()?;
        Ok(Self { node, signature })
    }
}

/// Verifies every node against the DeviceSet epoch in which it claims to
/// have been authored. Revoking a device later does not invalidate historical
/// nodes, while nodes claiming an epoch where the device was absent fail.
pub fn verify_nodes_with_history(
    nodes: &BTreeMap<SyncObjectId, SignedMessageNode>,
    history: &crate::DeviceSetHistory,
) -> Result<()> {
    for signed in nodes.values() {
        let signer = history.trusted_device(signed.node.trust_epoch, signed.node.author)?;
        signed.verify(signer)?;
    }
    Ok(())
}

/// Produces the same causal/stable display order on every device.
///
/// Each child must have `lamport > parent.lamport`. A device additionally has
/// a strict `author_previous` chain with an incrementing `device_counter`.
/// Independent ready nodes are ordered by `(lamport, author, counter, id)`.
pub fn stable_topological_order(
    nodes: &BTreeMap<SyncObjectId, SignedMessageNode>,
) -> Result<Vec<SyncObjectId>> {
    let mut indegree: BTreeMap<SyncObjectId, usize> = nodes.keys().map(|id| (*id, 0)).collect();
    let mut children: BTreeMap<SyncObjectId, Vec<SyncObjectId>> = BTreeMap::new();
    let mut seen_author_counter = BTreeSet::new();

    for (id, signed) in nodes {
        let node = &signed.node;
        if !seen_author_counter.insert((node.author, node.device_counter)) {
            return Err(SyncError::InvalidDagClock);
        }
        match node.author_previous {
            Some(previous) => {
                let previous_node = nodes.get(&previous).ok_or(SyncError::MissingParent)?;
                if previous_node.node.author != node.author
                    || previous_node.node.device_counter.checked_add(1) != Some(node.device_counter)
                    || !node.parents.contains(&previous)
                {
                    return Err(SyncError::InvalidDagClock);
                }
            }
            None if node.device_counter == 1 => {}
            None => return Err(SyncError::InvalidDagClock),
        }

        for parent in &node.parents {
            let parent_node = nodes.get(parent).ok_or(SyncError::MissingParent)?;
            if node.lamport <= parent_node.node.lamport {
                return Err(SyncError::InvalidDagClock);
            }
            *indegree.get_mut(id).ok_or(SyncError::Malformed)? += 1;
            children.entry(*parent).or_default().push(*id);
        }
    }

    let mut ready: BTreeSet<(u64, SyncDeviceId, u64, SyncObjectId)> = BTreeSet::new();
    for (id, degree) in &indegree {
        if *degree == 0 {
            let node = &nodes[id].node;
            ready.insert((node.lamport, node.author, node.device_counter, *id));
        }
    }

    let mut out = Vec::with_capacity(nodes.len());
    while let Some(next) = ready.pop_first() {
        let id = next.3;
        out.push(id);
        if let Some(kids) = children.get(&id) {
            for child in kids {
                let degree = indegree.get_mut(child).ok_or(SyncError::Malformed)?;
                *degree -= 1;
                if *degree == 0 {
                    let node = &nodes[child].node;
                    ready.insert((node.lamport, node.author, node.device_counter, *child));
                }
            }
        }
    }

    if out.len() != nodes.len() {
        return Err(SyncError::DagCycle);
    }
    Ok(out)
}
