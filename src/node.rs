use std::collections::BTreeMap;

use blsttc::{
  rand::{random, rngs::OsRng, RngCore}, PublicKey, SecretKey,
};
use sn_sdkg::{
  NodeId, DkgState
};

pub struct Node {
  node_id: NodeId,
  secret_key: SecretKey,
  pub pub_key: PublicKey,
  dkg_state: Option<DkgState>,
}

impl Node {
  pub fn new(node_id: NodeId) -> Self {
    let secret_key = random();
    let pub_key = SecretKey::public_key(&secret_key);

    Self {
      node_id,
      secret_key,
      pub_key,
      dkg_state: None,
    }
  }

  pub fn create_dkg_state(&mut self, threshold: usize, pub_keys: BTreeMap<NodeId, PublicKey>) {
    self.dkg_state = Some(DkgState::new(
      self.node_id,
      self.secret_key.clone(),
      pub_keys.clone(),
      threshold,
      &mut OsRng,
    ).expect("DKG state to be created"));
  }
}
