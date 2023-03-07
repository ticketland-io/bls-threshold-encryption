use std::collections::{BTreeMap, VecDeque};
use eyre::Result;
use sn_sdkg::{
  NodeId, DkgSignedVote, DkgState
};
use super::node::Node;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
  pub source: NodeId,
  pub dest: NodeId,
  pub vote: DkgSignedVote,
}

#[derive(Default)]
pub struct Net {
  pub nodes: Vec<Node>,
  pub packets: BTreeMap<NodeId, VecDeque<Packet>>,
  pub delivered_packets: Vec<Packet>,
}

impl Net {
  pub fn new(nodes: Vec<Node>) -> Self {
    Self {
      nodes,
      ..Default::default()
    }
  }

  pub fn broadcast(&mut self, source: NodeId, vote: DkgSignedVote) {
    let packets: Vec<Packet> = self.nodes.iter()
    .map(|node| DkgState::id(node.dkg_state.as_ref().unwrap()))
    .map(|dest| Packet {
      source,
      dest,
      vote: vote.clone(),
    })
    .collect();

    self.enqueue_packets(packets);
  }

  fn enqueue_packets(&mut self, packets: Vec<Packet>) {
    for packet in packets {
      self.packets
      .entry(packet.source)
      .or_default()
      .push_back(packet);
    }
  }

  pub fn drain_queued_packets(&mut self) -> Result<()> {
    while let Some(source) = self.packets.keys().next() {
      self.purge_empty_queues();
    }

    Ok(())
  }

  fn purge_empty_queues(&mut self) {
    self.packets = core::mem::take(&mut self.packets)
    .into_iter()
    .filter(|(_, queue)| !queue.is_empty())
    .collect();
  }
}
