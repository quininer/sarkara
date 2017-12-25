use rand::Rng;
use seckey::SecKey;
use dilithium::{ params, sign };
use super::Signature;
use ::Packing;


pub struct Dilithium;
pub struct PrivateKey(SecKey<[u8; params::SECRETKEYBYTES]>);
pub struct PublicKey([u8; params::PUBLICKEYBYTES]);
pub struct SignatureData([u8; params::BYTES]);

impl Signature for Dilithium {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Signature = SignatureData;

    fn keypair<R: Rng>(mut r: R) -> (Self::PrivateKey, Self::PublicKey) {
        let mut sk = SecKey::new([0; params::SECRETKEYBYTES]).ok().expect("memsec malloc fail.");
        let mut pk = [0; params::PUBLICKEYBYTES];
        sign::keypair(&mut r, &mut pk, &mut sk.write());
        (PrivateKey(sk), PublicKey(pk))
    }

    fn signature<R: Rng>(_r: R, sk: &Self::PrivateKey, data: &[u8]) -> Self::Signature {
        let mut sig = [0; params::BYTES];

        sign::sign(&mut sig, data, &*sk.0.read());

        SignatureData(sig)
    }

    fn verify(pk: &Self::PublicKey, sig: &Self::Signature, data: &[u8]) -> bool {
        sign::verify(data, &sig.0, &pk.0)
    }
}

impl Packing for PrivateKey {
    const LENGTH: usize = params::SECRETKEYBYTES;

    fn read_bytes(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&*self.0.read())
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::LENGTH {
            SecKey::new([0; params::SECRETKEYBYTES])
                .map(|mut sk| {
                    sk.write().copy_from_slice(buf);
                    PrivateKey(sk)
                })
                .ok()
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

impl Packing for SignatureData {
    const LENGTH: usize = params::BYTES;

    fn read_bytes(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0)
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::LENGTH {
            let mut sig = [0; params::BYTES];
            sig.copy_from_slice(buf);
            Some(SignatureData(sig))
        } else {
            None
        }
    }
}
