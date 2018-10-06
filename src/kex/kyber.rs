use arrayref::array_mut_ref;
use rand::{ Rng, CryptoRng };
use kyber::{ params, kem };
use crate::{ Packing, Error };
use super::{ KeyExchange, CheckedExchange };


pub struct Kyber;
pub struct PrivateKey([u8; params::SECRETKEYBYTES]);
pub struct PublicKey([u8; params::PUBLICKEYBYTES]);
pub struct Message([u8; params::CIPHERTEXTBYTES]);

impl KeyExchange for Kyber {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Message = Message;

    const SHARED_LENGTH: usize = params::SYMBYTES;

    fn keypair<R: Rng + CryptoRng>(mut r: R) -> (Self::PrivateKey, Self::PublicKey) {
        let mut sk = [0; params::SECRETKEYBYTES];

        let mut pk = [0; params::PUBLICKEYBYTES];
        kem::keypair(&mut r, &mut pk, &mut sk);
        (PrivateKey(sk), PublicKey(pk))
    }

    fn exchange_to<R: Rng + CryptoRng>(mut r: R, sharedkey: &mut [u8], &PublicKey(ref pk): &Self::PublicKey) -> Self::Message {
        let sharedkey = array_mut_ref!(sharedkey, 0, params::SYMBYTES);
        let mut c = [0; params::CIPHERTEXTBYTES];
        kem::enc(&mut r, &mut c, sharedkey, pk);
        Message(c)
    }

    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, m: &Self::Message) {
        let _ = <Kyber as CheckedExchange>::exchange_from(sharedkey, sk, m);
    }
}

impl CheckedExchange for Kyber {
    fn exchange_from(
        sharedkey: &mut [u8],
        &PrivateKey(ref sk): &Self::PrivateKey,
        &Message(ref m): &Self::Message
    ) -> Result<(), Error> {
        let sharedkey = array_mut_ref!(sharedkey, 0, params::SYMBYTES);
        if kem::dec(sharedkey, m, sk) {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

eq!(PrivateKey);
eq!(PublicKey);
eq!(Message);
packing!(PrivateKey; params::SECRETKEYBYTES);
packing!(PublicKey; params::PUBLICKEYBYTES);
packing!(Message; params::CIPHERTEXTBYTES);

#[cfg(feature = "serde")]
mod serde1 {
    use std::fmt;
    use serde::{
        Serialize, Serializer, Deserialize, Deserializer,
        de::{ self, Visitor }
    };
    use super::*;

    serde!(PrivateKey);
    serde!(PublicKey);
    serde!(Message);
}
