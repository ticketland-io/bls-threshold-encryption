use std::{collections::{BTreeMap, BTreeSet}};
use bls_threshold_encryption::{
  node::Node, net::Net,
};
use itertools::Itertools;
use log::info;
use blsttc::{rand::rngs::OsRng, PublicKey, PublicKeySet, Ciphertext};
use sn_sdkg::NodeId;

const NODE_COUNT: usize = 3;
const THRESHOLD: usize = 1;

fn main() {
  env_logger::init();

  let mut rng = OsRng;

  // create 10 nodes
  let mut nodes = (0..NODE_COUNT).map(|i| Node::new(i as u8)).collect::<Vec<_>>();

  // each node is assumed to know the public key's of every other node
  let pub_keys = nodes.iter().map(|node| (node.id, node.pub_key)).collect::<BTreeMap<NodeId, PublicKey>>();

  // Now we can init each node
  nodes.iter_mut().for_each(|node| node.init(THRESHOLD, &pub_keys, &mut rng));

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

  // check that everyone reached termination on the same pubkeyset i.e. all nodes have the same public key set
  let mut pubs = BTreeSet::new();
  for node in net.nodes.iter() {
    let (pks, _sks) = node
    .outcome()
    .expect("Unexpectedly failed to generate keypair")
    .unwrap();

    pubs.insert(pks);
  }

  assert!(pubs.len() == 1);

  let public_key_set = pubs.first().unwrap().clone();

  let original_msg = "This is a secret message we want to encrypt using the Pubic key set";
  let ciphertext = encrypt(&public_key_set, original_msg.as_bytes());
  info!("Cipher text is {:?}", hex::encode(ciphertext.to_bytes()));

  let plaintext = decrypt(&net, &public_key_set, &ciphertext.to_bytes());
  info!("Original plain text is {:?}", plaintext);
}

fn encrypt(pub_key_set: &PublicKeySet, msg: &[u8]) -> Ciphertext {
  pub_key_set.public_key().encrypt(msg)
}

fn decrypt(net: &Net, pub_key_set: &PublicKeySet, msg: &[u8]) -> String {
  let ciphertext = Ciphertext::from_bytes(msg).unwrap();

  let decryption_shares = net.nodes.iter()
  .enumerate()
  .map(|(idx, node)| {
    let sk_share = node
    .outcome()
    .expect("Unexpectedly failed to generate keypair")
    .unwrap()
    .1;

    let dec_share = sk_share.decrypt_share(&ciphertext).unwrap();
    assert!(pub_key_set.public_key_share(node.id() as usize).verify_decryption_share(&dec_share, &ciphertext));

    (idx, dec_share)
  })
  .collect::<BTreeMap<_, _>>();

  let dec_share_combinations = decryption_shares.iter().combinations(THRESHOLD + 1);
  let mut plaintext = BTreeSet::new();

  for dec_share in dec_share_combinations {
    let decrypted = pub_key_set.decrypt(dec_share, &ciphertext).unwrap();
    plaintext.insert(decrypted);
  }

  // Check that all combination of t + 1 can decrypt the message
  assert!(plaintext.len() == 1);

  std::str::from_utf8(plaintext.first().unwrap()).unwrap().to_string()
}
