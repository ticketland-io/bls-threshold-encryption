use sn_sdkg::{
  NodeId, DkgSignedVote
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
  pub source: NodeId,
  pub dest: NodeId,
  pub vote: DkgSignedVote,
}
