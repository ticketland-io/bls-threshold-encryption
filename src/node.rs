use blsttc::{
  rand::{random, rngs::OsRng}, PublicKey, SecretKey,
};
use sn_sdkg::{
  NodeId
};

pub struct Node {
  node_id: NodeId,
  secret_key: SecretKey,
  pub_key: PublicKey,
}

impl Node {
  pub fn new(node_id: NodeId) -> Self {
    let secret_key = random();
    let pub_key = SecretKey::public_key(&secret_key);

    Self {
      node_id,
      secret_key,
      pub_key,
    }
  }
}
