//! Public-key key exchange.
//!
//! Sarkara use [`NewHope`](https://eprint.iacr.org/2015/1092).


mod newhope;

pub use self::newhope::{ NewHope, PrivateKey };


/// `KeyExchange` trait.
pub trait KeyExchange {
    /// Private key.
    type PrivateKey;

    fn sk_length() -> usize;
    fn pk_length() -> usize;
    fn rec_length() -> usize;

    /// Generate keypair.
    fn keygen() -> (Self::PrivateKey, Vec<u8>);
    /// Key exchange, from Public key.
    fn exchange(sharedkey: &mut [u8], pk: &[u8]) -> Vec<u8>;
    /// key exchange, from Reconciliation data.
    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, rec: &[u8]);
}
