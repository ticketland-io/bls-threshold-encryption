use std::collections::BTreeMap;
use bls_threshold_encryption::{
  node::Node, net::Net,
};
use blsttc::{rand::rngs::OsRng, PublicKey};
use sn_sdkg::NodeId;

fn main() {
  let mut rng = OsRng;
  let node_count = 10;
  let threshold = 7;

  // create 10 nodes
  let mut nodes = (0..node_count).map(|i| Node::new(i)).collect::<Vec<_>>();

  // each node is assumed to know the public key's of every other node
  let pub_keys = nodes.iter().map(|node| (node.id, node.pub_key)).collect::<BTreeMap<NodeId, PublicKey>>();

  // Now we can init each node
  nodes.iter_mut().for_each(|node| node.init(threshold, &pub_keys, &mut rng));

  // Create a simulation of a network over which the nodes will be exchanging messages. This could easily be any statefull medium like a 
  // blockchain for example. Where nodes would store message on-chain via transactions.
  let mut net = Net::new(nodes);

  // broadcase every nodes first part votes
  let first_parts = net.nodes
  .iter_mut()
  .map(|node| (node.id(), node.first_vote().expect("get first vote")))
  .collect::<Vec<_>>();

  for (id, vote) in first_parts {
    net.broadcast(id, vote);
  }

  // let everyone vote
  net.drain_queued_packets(rng).expect("everyone votes");
}

