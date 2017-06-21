//! Public-key Signature.
//!
//! Sarkara use [`BLISS`](http://bliss.di.ens.fr/).

pub mod bliss;

use rand::{ Rand, Rng };
pub use self::bliss::Bliss;


/// `Signature` trait.
pub trait Signature {
    /// Private key.
    type PrivateKey;
    /// Public key.
    type PublicKey;
    /// Signature data.
    type Signature;

    /// Secret key length.
    const SK_LENGTH: usize;
    /// Public key length.
    const PK_LENGTH: usize;
    /// Signature length.
    const SIGN_LENGTH: usize;

    /// Generate keypair.
    fn keygen<R: Rand + Rng>() -> (Self::PrivateKey, Self::PublicKey);
    /// Signature.
    fn signature<R: Rand + Rng>(sk: &Self::PrivateKey, data: &[u8]) -> Self::Signature;
    /// Verify.
    fn verify(pk: &Self::PublicKey, sign: &Self::Signature, data: &[u8]) -> bool;
}
