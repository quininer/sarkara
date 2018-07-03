use rand::{ Rng, CryptoRng };
use seckey::SecKey;
use dilithium::{ params, sign };
use crate::{ Packing, Error };
use super::{ Signature, DeterministicSignature };


pub struct Dilithium;
pub struct PrivateKey(SecKey<[u8; params::SECRETKEYBYTES]>);
pub struct PublicKey([u8; params::PUBLICKEYBYTES]);
pub struct SignatureData([u8; params::BYTES]);

impl Signature for Dilithium {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Signature = SignatureData;

    fn keypair<R: Rng + CryptoRng>(mut r: R) -> (Self::PrivateKey, Self::PublicKey) {
        // TODO use `SecKey::with_default()`
        let mut sk = SecKey::new([0; params::SECRETKEYBYTES]).ok().expect("memsec malloc failed");
        let mut pk = [0; params::PUBLICKEYBYTES];
        sign::keypair(&mut r, &mut pk, &mut sk.write());
        (PrivateKey(sk), PublicKey(pk))
    }

    fn signature<R: Rng + CryptoRng>(_: R, sk: &Self::PrivateKey, data: &[u8]) -> Self::Signature {
        <Dilithium as DeterministicSignature>::signature(sk, data)
    }

    fn verify(
        &PublicKey(ref pk): &Self::PublicKey,
        &SignatureData(ref sig): &Self::Signature,
        data: &[u8]
    ) -> Result<(), Error> {
        if sign::verify(data, sig, pk) {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

impl DeterministicSignature for Dilithium {
    fn signature(&PrivateKey(ref sk): &Self::PrivateKey, data: &[u8]) -> Self::Signature {
        let mut sig = [0; params::BYTES];
        sign::sign(&mut sig, data, &sk.read());
        SignatureData(sig)
    }
}

impl Packing for PrivateKey {
    const BYTES_LENGTH: usize = params::SECRETKEYBYTES;

    fn read_bytes<F: FnOnce(&[u8])>(&self, f: F) {
        f(&*self.0.read());
    }

    fn from_bytes(buf: &[u8]) -> Self {
        let buf = array_ref!(buf, 0, params::SECRETKEYBYTES);
        SecKey::from_ref(buf)
            .map(PrivateKey)
            .expect("memsec malloc failed")
    }
}

impl Packing for PublicKey {
    const BYTES_LENGTH: usize = params::PUBLICKEYBYTES;

    fn read_bytes<F: FnOnce(&[u8])>(&self, f: F) {
        f(&self.0);
    }

    fn from_bytes(buf: &[u8]) -> Self {
        let buf = array_ref!(buf, 0, params::PUBLICKEYBYTES);
        let mut pk = [0; params::PUBLICKEYBYTES];
        pk.clone_from(buf);
        PublicKey(pk)
    }
}

impl Packing for SignatureData {
    const BYTES_LENGTH: usize = params::BYTES;

    fn read_bytes<F: FnOnce(&[u8])>(&self, f: F) {
        f(&self.0);
    }

    fn from_bytes(buf: &[u8]) -> Self {
        let buf = array_ref!(buf, 0, params::BYTES);
        let mut sig = [0; params::BYTES];
        sig.clone_from(buf);
        SignatureData(sig)
    }
}
