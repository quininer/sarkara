//! Public-key Signature.
//!
//! Sarkara use [`BLISS`](http://bliss.di.ens.fr/).

mod bliss;

pub use self::bliss::{ Bliss, PrivateKey, PublicKey, SignatureData };


/// `Signature` trait.
pub trait Signature {
    /// Private key.
    type PrivateKey;
    /// Public key.
    type PublicKey;
    /// Signature data.
    type Signature;

    /// Key generate.
    fn keygen() -> (Self::PrivateKey, Self::PublicKey);
    /// Signature.
    fn signature(sk: &Self::PrivateKey, data: &[u8]) -> Self::Signature;
    /// Verify.
    fn verify(pk: &Self::PublicKey, sign: &Self::Signature, data: &[u8]) -> bool;
}
