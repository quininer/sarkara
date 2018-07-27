use rand::{ Rng, CryptoRng };
use seckey::SecKey;
use kyber::{ params, kem };
use crate::{ Packing, Error };
use super::{ KeyExchange, CheckedExchange };


pub struct Kyber;
pub struct PrivateKey(SecKey<[u8; params::SECRETKEYBYTES]>);
pub struct PublicKey([u8; params::PUBLICKEYBYTES]);
pub struct Message([u8; params::CIPHERTEXTBYTES]);

impl KeyExchange for Kyber {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Message = Message;

    const SHARED_LENGTH: usize = params::SYMBYTES;

    fn keypair<R: Rng + CryptoRng>(mut r: R) -> (Self::PrivateKey, Self::PublicKey) {
        // TODO use `SecKey::with_default()`
        let mut sk = SecKey::new([0; params::SECRETKEYBYTES]).ok().expect("memsec malloc failed");

        let mut pk = [0; params::PUBLICKEYBYTES];
        kem::keypair(&mut r, &mut pk, &mut sk.write());
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
        if kem::dec(sharedkey, m, &sk.read()) {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

impl Packing for PrivateKey {
    const BYTES_LENGTH: usize = params::SECRETKEYBYTES;

    fn read_bytes<T, F>(&self, f: F)
        -> T
        where F: FnOnce(&[u8]) -> T
    {
        f(&*self.0.read())
    }

    fn from_bytes(buf: &[u8]) -> Self {
        let buf = array_ref!(buf, 0, params::SECRETKEYBYTES);
        SecKey::from_ref(buf).map(PrivateKey)
            .expect("memsec malloc failed")
    }
}

impl Packing for PublicKey {
    const BYTES_LENGTH: usize = params::PUBLICKEYBYTES;

    fn read_bytes<T, F>(&self, f: F)
        -> T
        where F: FnOnce(&[u8]) -> T
    {
        f(&self.0)
    }

    fn from_bytes(buf: &[u8]) -> Self {
        let buf = array_ref!(buf, 0, params::PUBLICKEYBYTES);
        let mut pk = [0; params::PUBLICKEYBYTES];
        pk.clone_from(buf);
        PublicKey(pk)
    }
}

impl Packing for Message {
    const BYTES_LENGTH: usize = params::CIPHERTEXTBYTES;

    fn read_bytes<T, F>(&self, f: F)
        -> T
        where F: FnOnce(&[u8]) -> T
    {
        f(&self.0)
    }

    fn from_bytes(buf: &[u8]) -> Self {
        let buf = array_ref!(buf, 0, params::CIPHERTEXTBYTES);
        let mut sig = [0; params::CIPHERTEXTBYTES];
        sig.clone_from(buf);
        Message(sig)
    }
}

#[cfg(feature = "serde")]
mod serde {
    use std::fmt;
    use serde::{
        Serialize, Serializer, Deserialize, Deserializer,
        de::{ self, Visitor }
    };
    use super::*;

    macro_rules! serde {
        ( $t:ident ) => {
            impl Serialize for $t {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where S: Serializer
                {
                    self.read_bytes(|bytes| serializer.serialize_bytes(bytes))
                }
            }

            impl<'de> Deserialize<'de> for $t {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where D: Deserializer<'de>
                {
                    struct BytesVisitor;

                    impl<'de> Visitor<'de> for BytesVisitor {
                        type Value = $t;

                        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                            formatter.write_str("a valid point in Ristretto format")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                            where E: de::Error
                        {
                            if v.len() == $t::BYTES_LENGTH {
                                Ok($t::from_bytes(v))
                            } else {
                                Err(de::Error::invalid_length(v.len(), &self))
                            }
                        }
                    }

                    deserializer.deserialize_bytes(BytesVisitor)
                }
            }
        }
    }

    serde!(PrivateKey);
    serde!(PublicKey);
    serde!(Message);
}
