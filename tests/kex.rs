extern crate rand;
extern crate sarkara;

use rand::{ChaChaRng, FromEntropy};
use sarkara::kex::kyber::Kyber;
use sarkara::kex::{CheckedExchange, KeyExchange};
use sarkara::{Error, Packing};

fn test_kex<KEX: KeyExchange>() {
    let (mut a, mut b) = (vec![0u8; KEX::SHARED_LENGTH], vec![0u8; KEX::SHARED_LENGTH]);
    let mut rng = ChaChaRng::from_entropy();

    let (ska, pka) = KEX::keypair(&mut rng);
    let msg = KEX::exchange_to(&mut rng, &mut b, &pka);
    KEX::exchange_from(&mut a, &ska, &msg);

    assert_eq!(a, b);
}

fn test_checkedkex<KEX: CheckedExchange>() {
    let (mut a, mut b) = (vec![0u8; KEX::SHARED_LENGTH], vec![0u8; KEX::SHARED_LENGTH]);
    let mut rng = ChaChaRng::from_entropy();

    let (ska, pka) = KEX::keypair(&mut rng);
    let msg = KEX::exchange_to(&mut rng, &mut b, &pka);

    let mut fake_msg = vec![0u8; KEX::Message::BYTES_LENGTH];
    msg.read_bytes(|msg| fake_msg.copy_from_slice(msg));
    fake_msg[0] ^= 0x42;
    fake_msg[KEX::Message::BYTES_LENGTH - 1] ^= 0x43;
    let fake_msg = KEX::Message::from_bytes(&fake_msg);

    let r = <KEX as CheckedExchange>::exchange_from(&mut a, &ska, &fake_msg);

    assert!(if let Err(Error::VerificationFailed) = r {
        true
    } else {
        false
    });
}

#[test]
fn test_kyber() {
    test_kex::<Kyber>();
    test_checkedkex::<Kyber>();
}
