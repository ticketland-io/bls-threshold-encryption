use std::collections::{BTreeMap, VecDeque};
use eyre::Result;
use blsttc::{
  rand::{rngs::OsRng},
};
use sn_sdkg::{
  NodeId, DkgSignedVote, DkgState, Error, VoteResponse
};
use log::info;
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

  pub fn drain_queued_packets(&mut self, mut rng: OsRng) -> Result<()> {
    while let Some(source) = self.packets.keys().next() {
      self.deliver_packet_from_source(*source, &mut rng)?;
      self.purge_empty_queues();
    }

    Ok(())
  }
  
  fn deliver_packet_from_source(&mut self, source: NodeId, rng: &mut OsRng) -> Result<()> {
    let Some(Some(packet)) = self.packets.get_mut(&source).map(|ps| ps.pop_front()) else {
      return Ok(())
    };

    self.purge_empty_queues();
    self.delivered_packets.push(packet.clone());

    let Some(dest_node) = self.nodes.get_mut(packet.dest as usize) else {
      info!("[NET] destination node does not exist, dropping packet for {:?}", packet.dest);
      return Ok(());
    };

    let resp = dest_node.handle_signed_vote(packet.vote.clone(), rng);
    info!("[NET] vote {:?} resp from {}: {:?}", packet.vote, packet.dest, resp);

    let vote_responses = match resp {
      Ok(res) => res,
      Err(Error::UnknownSender) => {
        assert!(self.nodes.len() as u8 <= packet.source);
        vec![]
      },
      Err(err) => return Err(err.into()),
    };

    for vote_response in vote_responses {
      match vote_response {
        VoteResponse::WaitingForMoreVotes => {},
        VoteResponse::BroadcastVote(vote) => {
          self.broadcast(packet.dest, *vote);
        },
        VoteResponse::RequestAntiEntropy => {
          // AE TODO
        },
        VoteResponse::DkgComplete(_, _) => {
          info!("[NET] DkgComplete for {:?}", packet.dest);
        }
      }
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
