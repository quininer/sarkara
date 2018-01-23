extern crate rand;
extern crate sarkara;

use rand::{ Rng, thread_rng };
use sarkara::sign::{ Signature, DeterministicSignature };


fn test_sign<SS: Signature>() {
    let mut data = vec![0; thread_rng().gen_range(1, 2049)];
    thread_rng().fill_bytes(&mut data);

    let (sk, pk) = SS::keypair(thread_rng());
    let sig = SS::signature(thread_rng(), &sk, &data);
    assert!(SS::verify(&pk, &sig, &data).is_ok());

    data[0] ^= 0x42;
    assert!(SS::verify(&pk, &sig, &data).is_err());
}

fn test_dsign<SS: DeterministicSignature>() {
    let mut data = vec![0; thread_rng().gen_range(1, 2049)];
    thread_rng().fill_bytes(&mut data);

    let (sk, pk) = SS::keypair(thread_rng());
    let sig = <SS as DeterministicSignature>::signature(&sk, &data);
    assert!(SS::verify(&pk, &sig, &data).is_ok());

    data[0] ^= 0x42;
    assert!(SS::verify(&pk, &sig, &data).is_err());
}


#[test]
fn test_dilithium() {
    use sarkara::sign::dilithium::Dilithium;

    test_sign::<Dilithium>();
    test_dsign::<Dilithium>();
}
