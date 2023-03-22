use ark_bls12_381::Bls12_381 as EllipticCurve;
use ark_std::{test_rng, rand::rngs::StdRng};
use ferveo::{
  PubliclyVerifiableDkg, Message, Params,
  vss::*,
};
use itertools::Itertools;
use ark_ec::PairingEngine;
use ark_poly::EvaluationDomain;
use ferveo_common::{Keypair, ExternalValidator};
use measure_time::print_time;
use tpke::{
  Ciphertext, DecryptionShareSimple, prepare_combine_simple,
  checked_decrypt_with_shared_secret,
};

type Fqk = <EllipticCurve as PairingEngine>::Fqk;

fn main() {
  let validator_keypairs = gen_keypairs(10);
  let dkg = setup_dealt_dkg(7, 10);
  
  let msg = "This is a secret message we want to encrypt using the Pubic key set".as_bytes();
  let aad: &[u8] = " additional_authenticated_data".as_bytes();
  let ciphertext = encrypt(&dkg, msg, aad);
  let (_, _, shared_secret) = decrypt(&dkg, aad, &ciphertext, &validator_keypairs);

  let plaintext = checked_decrypt_with_shared_secret(
    &ciphertext,
    aad,
    &dkg.pvss_params.g_inv(),
    &shared_secret,
  ).unwrap();

  assert_eq!(plaintext, msg);

  println!("Plaintext: {}", String::from_utf8(plaintext).unwrap());
}

/// Encrypts using the threshold public key for the given dkg session
fn encrypt(dkg: &PubliclyVerifiableDkg<EllipticCurve>, msg: &[u8], aad: &[u8]) -> Ciphertext<EllipticCurve> {
  let rng = &mut test_rng();
  let public_key = dkg.final_key();
  
  tpke::encrypt::<_, EllipticCurve>(msg, aad, &public_key, rng)
}

fn decrypt(
  dkg: &PubliclyVerifiableDkg<EllipticCurve>,
  aad: &[u8],
  ciphertext: &Ciphertext<EllipticCurve>,
  validator_keypairs: &[Keypair<EllipticCurve>],
) -> (
  PubliclyVerifiableSS<EllipticCurve, Aggregated>,
  Vec<DecryptionShareSimple<EllipticCurve>>,
  Fqk,
) {
  // Make sure validators are in the same order dkg is by comparing their public keys
  dkg.validators
  .iter()
  .zip_eq(validator_keypairs.iter())
  .for_each(|(v, k)| {
    assert_eq!(v.validator.public_key, k.public());
  });

  let pvss_aggregated = aggregate(dkg);

  let decryption_shares = validator_keypairs
  .iter()
  .enumerate()
  .map(|(validator_index, validator_keypair)| {
    pvss_aggregated.make_decryption_share_simple(
      ciphertext,
      aad,
      &validator_keypair.decryption_key,
      validator_index,
      &dkg.pvss_params.g_inv(),
    )
  })
  .collect::<Vec<DecryptionShareSimple<EllipticCurve>>>();

  let domain = &dkg
  .domain
  .elements()
  .take(decryption_shares.len())
  .collect::<Vec<_>>();
  
  assert_eq!(domain.len(), decryption_shares.len());

  let lagrange_coeffs = prepare_combine_simple::<EllipticCurve>(domain);

  let shared_secret = tpke::share_combine_simple::<EllipticCurve>(
    &decryption_shares,
    &lagrange_coeffs,
  );

  (pvss_aggregated, decryption_shares, shared_secret)
}

/// Set up a dkg with enough pvss transcripts to meet the threshold
fn setup_dealt_dkg(security_threshold: u32, shares: u32) -> PubliclyVerifiableDkg<EllipticCurve> {
  let rng = &mut ark_std::test_rng();

  // gather everyone's transcripts
  let mut transcripts = vec![];
  
  for i in 0..security_threshold {
    let mut dkg = setup_dkg(i as usize, security_threshold, shares);
    transcripts.push(dkg.share(rng).expect("Test failed"));
  }

  // our test dkg
  let mut dkg = setup_dkg(0, security_threshold, shares);

  // iterate over transcripts from lowest weight to highest
  for (sender, pvss) in transcripts.into_iter().enumerate() {
    if let Message::Deal(ss) = pvss.clone() {
      print_time!("PVSS verify pvdkg");
      ss.verify_full(&dkg);
    }
    
    dkg.apply_message(
      dkg.validators[sender].validator.clone(),
      pvss,
    )
    .expect("Setup failed");
  }

  dkg
}

/// Create a test dkg in state [`DkgState::Init`]
pub fn setup_dkg(
  validator: usize,
  security_threshold: u32,
  shares_num: u32,
) -> PubliclyVerifiableDkg<EllipticCurve> {
  let keypairs = gen_keypairs(shares_num);
  let validators = gen_validators(&keypairs);
  let me = validators[validator].clone();
  
  PubliclyVerifiableDkg::new(
    validators,
    Params {
      tau: 0,
      security_threshold,
      shares_num,
    },
    &me,
    keypairs[validator],
  )
  .expect("Setup failed")
}

/// Generate a set of keypairs for each validator
pub fn gen_keypairs(shares_num: u32) -> Vec<Keypair<EllipticCurve>> {
  let rng = &mut ark_std::test_rng();
  (0..shares_num).map(|_| Keypair::<EllipticCurve>::new(rng)).collect()
}

/// Generate a few validators
pub fn gen_validators(keypairs: &[Keypair<EllipticCurve>]) -> Vec<ExternalValidator<EllipticCurve>> {
  (0..keypairs.len())
  .map(|i| ExternalValidator {
    address: format!("validator_{}", i),
    public_key: keypairs[i].public(),
  })
  .collect()
}
