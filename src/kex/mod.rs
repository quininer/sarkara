//! Public-key key exchange.
//!
//! Sarkara use [`NewHope`](https://eprint.iacr.org/2015/1092).


mod newhope;

pub use self::newhope::{ NewHope, PrivateKey };


/// `KeyExchange` trait.
pub trait KeyExchange {
    /// Private key.
    type PrivateKey;
    /// Public key.
    type PublicKey;
    /// Reconciliation data.
    type Reconciliation;

    /// Generate keypair.
    fn keygen() -> (Self::PrivateKey, Self::PublicKey);
    /// Key exchange, from Public key.
    fn exchange(sharedkey: &mut [u8], pk: &Self::PublicKey) -> Self::Reconciliation;
    /// key exchange, from Reconciliation data.
    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, rec: &Self::Reconciliation);
}
