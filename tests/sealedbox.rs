extern crate rand;
extern crate sarkara;

use rand::{thread_rng, Rng, ThreadRng};
use sarkara::aead::AeadCipher;
use sarkara::kex::KeyExchange;
use sarkara::sealedbox::SealedBox;

use sarkara::kex::kyber::Kyber;
use sarkara::aead::sparx256colm0::Sparx256Colm0;
use sarkara::aead::norx6441::Norx6441;

fn test_sealedbox<K: KeyExchange, AE: AeadCipher>() {
    let (bob_priv, bob_pub) = K::keypair(thread_rng());

    let (alice_msg, alice_enc) = K::send::<ThreadRng, AE>(thread_rng(), &bob_pub);
    let bob_dec = K::recv::<AE>(&bob_priv, &alice_msg);

    let mut nonce = vec![0; AE::NONCE_LENGTH];
    let mut aad = vec![0; thread_rng().gen_range(0, 34)];
    let mut pt = vec![0; 32];
    let mut ct = vec![0; pt.len() + AE::TAG_LENGTH];
    let mut ot = vec![0; pt.len()];

    thread_rng().fill_bytes(&mut nonce);
    thread_rng().fill_bytes(&mut aad);
    thread_rng().fill_bytes(&mut pt);

    alice_enc.seal(&nonce, &aad, &pt, &mut ct).unwrap();
    let r = bob_dec.open(&nonce, &aad, &ct, &mut ot).unwrap();

    assert!(r);
    assert_eq!(pt, ot);
}

#[test]
fn test_kyber_sparx256colm0() {
    test_sealedbox::<Kyber, Sparx256Colm0>();
}

#[test]
fn test_kyber_norx() {
    test_sealedbox::<Kyber, Norx6441>();
}
