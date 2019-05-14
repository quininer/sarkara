extern crate rand;
extern crate sarkara;

use rand::{ChaChaRng, FromEntropy, Rng, RngCore};
use sarkara::aead::AeadCipher;
use sarkara::kex::KeyExchange;
use sarkara::sealedbox::SealedBox;

use sarkara::aead::norx6441::Norx6441;
use sarkara::kex::kyber::Kyber;

fn test_sealedbox<KEX: KeyExchange, AE: AeadCipher>() {
    let mut rng = ChaChaRng::from_entropy();
    let (bob_priv, bob_pub) = KEX::keypair(&mut rng);

    let (alice_msg, alice_enc) = SealedBox::<KEX, AE>::send(&mut rng, &bob_pub);
    let bob_dec = SealedBox::<KEX, AE>::recv(&bob_priv, &alice_msg);

    let mut nonce = vec![0u8; AE::NONCE_LENGTH];
    let mut aad = vec![0u8; rng.gen_range(0, 34)];
    let mut pt = vec![0u8; 32];
    let mut ct = vec![0u8; pt.len() + AE::TAG_LENGTH];
    let mut ot = vec![0u8; pt.len()];

    rng.fill_bytes(&mut nonce);
    rng.fill_bytes(&mut aad);
    rng.fill_bytes(&mut pt);

    alice_enc.seal(&nonce, &aad, &pt, &mut ct).unwrap();
    bob_dec.open(&nonce, &aad, &ct, &mut ot).unwrap();

    assert_eq!(pt, ot);
}

#[test]
fn test_kyber_norx() {
    test_sealedbox::<Kyber, Norx6441>();
}
