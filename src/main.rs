use std::collections::{BTreeMap, BTreeSet};
use bls_threshold_encryption::{
  node::Node, net::Net,
};
use log::info;
use blsttc::{rand::rngs::OsRng, PublicKey};
use sn_sdkg::NodeId;

fn main() {
  env_logger::init();

  let mut rng = OsRng;
  let node_count = 3;
  let threshold = 1;

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

  // check that everyone reached termination on the same pubkeyset
  let mut pubs = BTreeSet::new();
  for node in net.nodes.into_iter() {
    let (pks, _sks) = node
    .outcome()
    .expect("Unexpectedly failed to generate keypair")
    .unwrap();

    pubs.insert(pks);
  }

  assert!(pubs.len() == 1);
  info!(">>>>>> {:?}", pubs);
}

