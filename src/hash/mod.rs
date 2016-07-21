//! Hashing.
//!
//! Sarkara use [`BLAKE2b`](https://blake2.net/),
//! it based on [`ChaCha`](https://en.wikipedia.org/wiki/ChaCha_(cipher)) stream cipher,
//! have good performance and security.

mod blake2;

pub use self::blake2::Blake2b;


/// `Hash` trait.
pub trait Hash: Default {
    /// Hash digest.
    type Digest;

    /// Calculate hash.
    fn hash(&self, data: &[u8]) -> Self::Digest;
}

/// `GenericHash` trait,
/// allow set output length and key.
pub trait GenericHash: Default + Hash {
    /// Set output length.
    fn with_size(&mut self, nn: usize) -> &mut Self;
    /// Set hash key.
    fn with_key(&mut self, key: &[u8]) -> &mut Self;
}
