use rand::Rng;
use seckey::SecKey;
use kyber::{ params, kem };
use super::{ KeyExchange, CheckedExchange };
use ::Packing;


pub struct Kyber;
pub struct PrivateKey(pub SecKey<[u8; params::SECRETKEYBYTES]>);
pub struct PublicKey(pub [u8; params::PUBLICKEYBYTES]);
pub struct Message(pub [u8; params::CIPHERTEXTBYTES]);

impl KeyExchange for Kyber {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Message = Message;

    const SHARED_LENGTH: usize = params::SYMBYTES;

    fn kerpair<R: Rng>(mut r: R) -> (Self::PrivateKey, Self::PublicKey) {
        // TODO use `SecKey::with_default()`
        let mut sk = SecKey::new([0; params::SECRETKEYBYTES]).ok().expect("memsec malloc failed");

        let mut pk = [0; params::PUBLICKEYBYTES];
        kem::keypair(&mut r, &mut pk, &mut sk.write());
        (PrivateKey(sk), PublicKey(pk))
    }

    fn exchange_to<R: Rng>(mut r: R, sharedkey: &mut [u8], &PublicKey(ref pk): &Self::PublicKey) -> Self::Message {
        let sharedkey = array_mut_ref!(sharedkey, 0, params::SYMBYTES);
        let mut c = [0; params::CIPHERTEXTBYTES];
        kem::enc(&mut r, &mut c, sharedkey, pk);
        Message(c)
    }

    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, m: &Self::Message) {
        <Kyber as CheckedExchange>::exchange_from(sharedkey, sk, m);
    }
}

impl CheckedExchange for Kyber {
    fn exchange_from(
        sharedkey: &mut [u8],
        &PrivateKey(ref sk): &Self::PrivateKey,
        &Message(ref m): &Self::Message
    ) -> bool {
        let sharedkey = array_mut_ref!(sharedkey, 0, params::SYMBYTES);
        kem::dec(sharedkey, &m, &sk.read())
    }
}

impl Packing for PrivateKey {
    const BYTES_LENGTH: usize = params::SECRETKEYBYTES;

    fn read_bytes(&self, buf: &mut [u8]) {
        let buf = array_mut_ref!(buf, 0, params::SECRETKEYBYTES);
        buf.clone_from(&*self.0.read())
    }

    fn from_bytes(buf: &[u8]) -> Self {
        let buf = array_ref!(buf, 0, params::SECRETKEYBYTES);
        SecKey::from_ref(buf).map(PrivateKey)
            .expect("memsec malloc failed")
    }
}

impl Packing for PublicKey {
    const BYTES_LENGTH: usize = params::PUBLICKEYBYTES;

    fn read_bytes(&self, buf: &mut [u8]) {
        let buf = array_mut_ref!(buf, 0, params::PUBLICKEYBYTES);
        buf.clone_from(&self.0)
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

    fn read_bytes(&self, buf: &mut [u8]) {
        let buf = array_mut_ref!(buf, 0, params::CIPHERTEXTBYTES);
        buf.clone_from(&self.0)
    }

    fn from_bytes(buf: &[u8]) -> Self {
        let buf = array_ref!(buf, 0, params::CIPHERTEXTBYTES);
        let mut sig = [0; params::CIPHERTEXTBYTES];
        sig.clone_from(buf);
        Message(sig)
    }
}
