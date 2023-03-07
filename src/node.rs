use blsttc::{
  rand::{random, rngs::OsRng}, PublicKey, SecretKey,
};
pub struct Node {
  secret_key: SecretKey,
  pub_key: PublicKey,
}

impl Node {
  pub fn new() -> Self {
    let secret_key = random();
    let pub_key = SecretKey::public_key(&secret_key);

    Self {
      secret_key,
      pub_key,
    }
  }
}
