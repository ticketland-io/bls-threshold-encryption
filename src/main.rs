use std::collections::BTreeMap;
use bls_threshold_encryption::node::Node;
use blsttc::PublicKey;
use sn_sdkg::NodeId;

fn main() {
  let node_count = 10;
  let threshold = 7;

  // create 10 nodes
  let mut nodes = (0..node_count).map(|i| Node::new(i)).collect::<Vec<_>>();

  // each node is assumed to know the public key's of every other node
  let pub_keys = nodes.iter().map(|node| (node.id, node.pub_key)).collect::<BTreeMap<NodeId, PublicKey>>();

  // Now we can init each node
  nodes.iter_mut().for_each(|node| node.init(threshold, &pub_keys));
}

