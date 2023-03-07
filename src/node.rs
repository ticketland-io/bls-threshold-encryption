use std::{collections::BTreeMap, ops::{Deref, DerefMut}};
use blsttc::{
  rand::{random, rngs::OsRng}, PublicKey, SecretKey,
};
use sn_sdkg::{
  NodeId, DkgState
};

pub struct Node {
  pub id: NodeId,
  pub pub_key: PublicKey,
  pub dkg_state: Option<DkgState>,
  secret_key: SecretKey,
}

impl Node {
  pub fn new(id: NodeId) -> Self {
    let secret_key = random();
    let pub_key = SecretKey::public_key(&secret_key);

    Self {
      id,
      secret_key,
      pub_key,
      dkg_state: None,
    }
  }

  pub fn init(&mut self, threshold: usize, pub_keys: &BTreeMap<NodeId, PublicKey>) {
    self.dkg_state = Some(DkgState::new(
      self.id,
      self.secret_key.clone(),
      pub_keys.clone(),
      threshold,
      &mut OsRng,
    ).expect("DKG state to be created"));
  }
}

impl Deref for Node {
  type Target = DkgState;

  fn deref(&self) -> &Self::Target {
    self.dkg_state.as_ref().expect("state to be initialized")
  }
}

impl DerefMut for Node {
  fn deref_mut(&mut self) -> &mut Self::Target {
    self.dkg_state.as_mut().expect("state to be initialized")
  }
}
