extern crate rand;
extern crate sarkara;

use rand::thread_rng;
use sarkara::{ Packing, Error };
use sarkara::kex::{ KeyExchange, CheckedExchange };


fn test_kex<KEX: KeyExchange>() {
    let (mut a, mut b) = (vec![0; KEX::SHARED_LENGTH], vec![0; KEX::SHARED_LENGTH]);

    let (ska, pka) = KEX::keypair(thread_rng());
    let msg = KEX::exchange_to(thread_rng(), &mut b, &pka);
    KEX::exchange_from(&mut a, &ska, &msg);

    assert_eq!(a, b);
}

fn test_checkedkex<KEX: CheckedExchange>() {
    let (mut a, mut b) = (vec![0; KEX::SHARED_LENGTH], vec![0; KEX::SHARED_LENGTH]);

    let (ska, pka) = KEX::keypair(thread_rng());
    let msg = KEX::exchange_to(thread_rng(), &mut b, &pka);

    let mut fake_msg = vec![0; KEX::Message::BYTES_LENGTH];
    msg.read_bytes(&mut fake_msg);
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
    use sarkara::kex::kyber::Kyber;

    test_kex::<Kyber>();
    test_checkedkex::<Kyber>();
}

#[cfg(feature = "extra")]
#[test]
fn test_sidh() {
    use sarkara::kex::sidh::Sidh;

    test_kex::<Sidh>();
}
