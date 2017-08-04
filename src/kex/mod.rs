//! Public-key key exchange.
//!
//! Sarkara use [`NewHope`](https://eprint.iacr.org/2015/1092).


pub mod newhope;
pub mod kyber;

use rand::{ Rand, Rng };
pub use self::newhope::NewHope;
pub use self::kyber::Kyber;


/// `KeyExchange` trait.
pub trait KeyExchange {
    /// Private key.
    type PrivateKey;
    /// Public key.
    type PublicKey;
    /// Reconciliation data.
    type Reconciliation;

    /// Secret key length.
    const SK_LENGTH: usize;
    /// Public key length.
    const PK_LENGTH: usize;
    /// Reconciliation data length.
    const REC_LENGTH: usize;

    /// Generate keypair.
    fn keygen<R: Rand + Rng>() -> (Self::PrivateKey, Self::PublicKey);
    /// Key exchange, from Public key.
    fn exchange<R: Rand + Rng>(sharedkey: &mut [u8], pk: &Self::PublicKey) -> Self::Reconciliation;
    /// key exchange, from Reconciliation data.
    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, rec: &Self::Reconciliation);
}
