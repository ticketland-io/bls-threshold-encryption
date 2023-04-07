use ark_bls12_381::{
  Bls12_381 as EllipticCurve, Fr,
};
use ark_std::{Zero, rand::{rngs::{StdRng, OsRng}, SeedableRng}};
use ferveo::{
  PubliclyVerifiableDkg, Message, Params,
  pvss::*,
};
use itertools::Itertools;
use ark_ec::{pairing::Pairing};
use ark_poly::EvaluationDomain;
use ferveo_common::{Keypair, ExternalValidator};
use measure_time::print_time;
use tpke::{
  Ciphertext, DecryptionShareSimple, prepare_combine_simple,
  decrypt_with_shared_secret,
};

type Fqk = <EllipticCurve as Pairing>::TargetField;

struct ValidatorData {
  keypair: Keypair<EllipticCurve>,
  validator: ExternalValidator<EllipticCurve>,
  rng: StdRng,
}

fn main() {
  let msg = "This is a secret message we want to encrypt using the Pubic key set".as_bytes();
  let aad: &[u8] = " additional_authenticated_data".as_bytes();

  let mut validators = gen_validators(4);
  let dkgs = setup_dealt_dkg(3, 4, &mut validators);

  // Each dkg setup yields a different final_key, however all of them can be used to encrypt data 
  // that will be later decrypted by each dkg (node) calculating its' decryption share
  for dkg in &dkgs {
    let ciphertext = encrypt(&dkg, msg, aad);

    let keypairs = validators.iter().map(|v| v.keypair.clone()).collect::<Vec<_>>();
    let decryption_shares = decrypt(&dkg, &dkgs, aad, &ciphertext, &keypairs);

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

    let plaintext = decrypt_with_shared_secret(
      &ciphertext,
      aad,
      &shared_secret,
      &dkg.pvss_params.g_inv(),
    ).unwrap();

    assert_eq!(plaintext, msg);
    println!("Plaintext: {}", String::from_utf8(plaintext).unwrap());
  }
}

/// Encrypts using the threshold public key for the given dkg session
fn encrypt(dkg: &PubliclyVerifiableDkg<EllipticCurve>, msg: &[u8], aad: &[u8]) -> Ciphertext<EllipticCurve> {
  let mut rng = StdRng::from_rng(OsRng).expect("create StdRng");
  let public_key = dkg.final_key();

  tpke::encrypt::<EllipticCurve>(msg, aad, &public_key, &mut rng).expect("encrypt")
}

fn decrypt(
  dkg: &PubliclyVerifiableDkg<EllipticCurve>,
  dkgs: &Vec<PubliclyVerifiableDkg<EllipticCurve>>,
  aad: &[u8],
  ciphertext: &Ciphertext<EllipticCurve>,
  validator_keypairs: &[Keypair<EllipticCurve>],
) -> Vec<DecryptionShareSimple<EllipticCurve>> {
  // Make sure validators are in the same order dkg is by comparing their public keys
  dkg.validators
  .iter()
  .zip_eq(validator_keypairs.iter())
  .for_each(|(v, k)| {
    assert_eq!(v.validator.public_key, k.public());
  });

  let decryption_shares = validator_keypairs
  .iter()
  .enumerate()
  .map(|(validator_index, validator_keypair)| {
    let pvss_aggregated = aggregate(&dkgs[validator_index]);

    pvss_aggregated.make_decryption_share_simple(
      ciphertext,
      aad,
      &validator_keypair.decryption_key,
      validator_index,
      &dkgs[validator_index].pvss_params.g_inv(),
    ).expect("decryption share")
  })
  .collect::<Vec<DecryptionShareSimple<EllipticCurve>>>();

  decryption_shares
}

/// We're going to refresh the shares and check that the shared secret is the same
fn _decrypt_after_share_refresh(
  _current_shared_secret: Fqk,
  dkg: &PubliclyVerifiableDkg<EllipticCurve>,
  aad: &[u8],
  ciphertext: &Ciphertext<EllipticCurve>,
  validator_keypairs: &[Keypair<EllipticCurve>],
) {
  let mut rng = StdRng::from_rng(OsRng).expect("create StdRng");
  let pvss_aggregated = aggregate(dkg);

  // Dealer computes a new random polynomial with constant term x_r = 0
  let polynomial = tpke::make_random_polynomial_at::<EllipticCurve>(
    dkg.params.security_threshold as usize,
    &Fr::zero(),
    &mut rng,
  );

  // Now Dealer has to share this polynomial with participants

  // Participants computes new decryption shares
  let new_decryption_shares = validator_keypairs
  .iter()
  .enumerate()
  .map(|(validator_index, validator_keypair)| {
    pvss_aggregated.refresh_decryption_share(
      &ciphertext,
      aad,
      &validator_keypair.decryption_key,
      validator_index,
      &polynomial,
      &dkg,
    ).expect("refresh share")
  })
  .collect::<Vec<DecryptionShareSimple<EllipticCurve>>>();

  // At this point we can create a new shared secret
  let domain = &dkg.domain.elements().collect::<Vec<_>>();
  let lagrange_coeffs = tpke::prepare_combine_simple::<EllipticCurve>(domain);
  let _new_shared_secret = tpke::share_combine_simple::<EllipticCurve>(
    &new_decryption_shares,
    &lagrange_coeffs,
  );
}

/// Set up a dkg with enough pvss transcripts to meet the threshold
fn setup_dealt_dkg(
  security_threshold: u32,
  shares: u32,
  validators: &mut Vec<ValidatorData>,
) -> Vec<PubliclyVerifiableDkg<EllipticCurve>> {
  // gather everyone's transcripts
  let mut transcripts = vec![];
  let mut dkgs = vec![];

  let validators = validators;
  for i in 0..shares {
    let rng = &mut validators[i as usize].rng.clone();
    let mut dkg = setup_dkg(i as usize, security_threshold, shares, validators);
    let share = dkg.share(rng).expect("Test failed");

    transcripts.push(share);
    dkgs.push(dkg);
  }

  // Every validator should apply every transcript from other validators
  for dkg in dkgs.iter_mut() {
    for (sender, pvss) in transcripts.iter().enumerate() {
      if let Message::Deal(ss) = pvss.clone() {
        print_time!("PVSS verify pvdkg");
        ss.verify_full(&dkg);
      }
      
      dkg.apply_message(
        dkg.validators[sender].validator.clone(),
        pvss.clone(),
      )
      .expect("Setup failed");
    }
  }

  dkgs
}

/// Create a test dkg in state [`DkgState::Init`]
fn setup_dkg(
  validator: usize,
  security_threshold: u32,
  shares_num: u32,
  validators: &mut Vec<ValidatorData>,
) -> PubliclyVerifiableDkg<EllipticCurve> {
  let me = validators[validator].validator.clone();
  let keypair = validators[validator].keypair.clone();
  let validators = validators.iter().map(|v| v.validator.clone()).collect::<Vec<ExternalValidator<EllipticCurve>>>();

  let dkg = PubliclyVerifiableDkg::new(
    &validators,
    Params {
      tau: 0,
      security_threshold,
      shares_num,
    },
    &me,
    keypair,
  )
  .expect("Setup failed");

  dkg
}

/// Generate a few validators
fn gen_validators(shares_num: u32) -> Vec<ValidatorData> {
  (0..shares_num)
  .map(|i| {
    let mut rng = StdRng::from_rng(OsRng).expect("create StdRng");
    let keypair = Keypair::<EllipticCurve>::new(&mut rng);
    let validator = ExternalValidator {
      address: format!("validator_{}", i),
      public_key: keypair.public(),
    };

    ValidatorData {keypair, validator, rng}
  })
  .collect()
}
