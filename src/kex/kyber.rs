use rand::Rng;
use seckey::SecKey;
use kyber::{ params, kem };
use super::KeyExchange;
use ::Packing;


pub struct Kyber;
pub struct PrivateKey(SecKey<[u8; params::SECRETKEYBYTES]>);
pub struct PublicKey([u8; params::PUBLICKEYBYTES]);
pub struct Message([u8; params::CIPHERTEXTBYTES]);

impl KeyExchange for Kyber {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Message = Message;

    const SHARED_LENGTH: usize = params::SYMBYTES;

    fn kerpair<R: Rng>(mut r: R) -> (Self::PrivateKey, Self::PublicKey) {
        // TODO use `SecKey::with_default()`
        let mut sk = SecKey::new([0; params::SECRETKEYBYTES]).ok().expect("memsec malloc fail.");

        let mut pk = [0; params::PUBLICKEYBYTES];
        kem::keypair(&mut r, &mut pk, &mut sk.write());
        (PrivateKey(sk), PublicKey(pk))
    }

    fn exchange_to<R: Rng>(mut r: R, sharedkey: &mut [u8], pk: &Self::PublicKey) -> Self::Message {
        let sharedkey = array_mut_ref!(sharedkey, 0, params::SYMBYTES);
        let mut c = [0; params::CIPHERTEXTBYTES];
        kem::enc(&mut r, &mut c, sharedkey, &pk.0);
        Message(c)
    }

    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, m: &Self::Message) -> bool {
        let sharedkey = array_mut_ref!(sharedkey, 0, params::SYMBYTES);
        kem::dec(sharedkey, &m.0, &sk.0.read())
    }
}

impl Packing for PrivateKey {
    const LENGTH: usize = params::SECRETKEYBYTES;

    fn read_bytes(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&*self.0.read())
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::LENGTH {
            let buf = array_ref!(buf, 0, params::SECRETKEYBYTES);
            SecKey::from_ref(buf).map(PrivateKey)
        } else {
            None
        }
    }
}

impl Packing for PublicKey {
    const LENGTH: usize = params::PUBLICKEYBYTES;

    fn read_bytes(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0)
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::LENGTH {
            let mut pk = [0; params::PUBLICKEYBYTES];
            pk.copy_from_slice(buf);
            Some(PublicKey(pk))
        } else {
            None
        }
    }
}

impl Packing for Message {
    const LENGTH: usize = params::CIPHERTEXTBYTES;

    fn read_bytes(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0)
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::LENGTH {
            let mut sig = [0; params::CIPHERTEXTBYTES];
            sig.copy_from_slice(buf);
            Some(Message(sig))
        } else {
            None
        }
    }
}
