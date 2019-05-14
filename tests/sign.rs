extern crate rand;
extern crate sarkara;

use rand::{ChaChaRng, FromEntropy, Rng, RngCore};
use sarkara::sign::dilithium::Dilithium;
use sarkara::sign::{DeterministicSignature, Signature};

fn test_sign<SS: Signature>() {
    let mut rng = ChaChaRng::from_entropy();
    let mut data = vec![0; rng.gen_range(1, 2049)];
    rng.fill_bytes(&mut data);

    let (sk, pk) = SS::keypair(&mut rng);
    let sig = SS::signature(&mut rng, &sk, &data);
    assert!(SS::verify(&pk, &sig, &data).is_ok());

    data[0] ^= 0x42;
    assert!(SS::verify(&pk, &sig, &data).is_err());
}

fn test_dsign<SS: DeterministicSignature>() {
    let mut rng = ChaChaRng::from_entropy();
    let mut data = vec![0; rng.gen_range(1, 2049)];
    rng.fill_bytes(&mut data);

    let (sk, pk) = SS::keypair(&mut rng);
    let sig = <SS as DeterministicSignature>::signature(&sk, &data);
    assert!(SS::verify(&pk, &sig, &data).is_ok());

    data[0] ^= 0x42;
    assert!(SS::verify(&pk, &sig, &data).is_err());
}

#[test]
fn test_dilithium() {
    test_sign::<Dilithium>();
    test_dsign::<Dilithium>();
}
