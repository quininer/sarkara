use seckey::Key;
use super::Signature;

pub use blissb::{ PublicKey, Signature as SignatureData };


/// BLISS Signature Scheme.
///
/// # Example(signature)
/// ```
/// use sarkara::sign::{ Bliss, Signature };
///
/// let data = [9; 64];
/// let (sk, pk) = Bliss::keygen();
/// let sign = Bliss::signature(&sk, &data);
/// assert!(Bliss::verify(&pk, &sign, &data));
/// assert!(!Bliss::verify(&pk, &sign, &data[1..]));
/// ```
pub struct Bliss;

impl Signature for Bliss {
    type PrivateKey = PrivateKey;
    type PublicKey = ::blissb::PublicKey;
    type Signature = ::blissb::Signature;

    fn keygen() -> (Self::PrivateKey, Self::PublicKey) {
        let sk = ::blissb::PrivateKey::new().unwrap();
        let pk = sk.public();
        (PrivateKey(sk.into()), pk)
    }

    fn signature(&PrivateKey(ref sk): &Self::PrivateKey, data: &[u8]) -> Self::Signature {
        sk.signature(data).unwrap()
    }

    fn verify(pk: &Self::PublicKey, sign: &Self::Signature, data: &[u8]) -> bool {
        pk.verify(sign, data)
    }
}

/// BLISS private key.
pub struct PrivateKey(pub Key<::blissb::PrivateKey>);
