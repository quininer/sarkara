//! Secret-key encryption.
//!
//! Sarkara use [`hc256`](http://www.ecrypt.eu.org/stream/hcpf.html),
//! it is one of [`eSTREAM`](http://www.ecrypt.eu.org/stream/) portfolio,
//! have good design and performance.

mod hc256;

pub use self::hc256::HC256;


/// `StreamCipher` trait.
pub trait StreamCipher {
    /// Create a new StreamCipher.
    fn new(key: &[u8]) -> Self;

    /// Key length.
    fn key_length() -> usize;
    /// Nonce length.
    fn nonce_length() -> usize;

    /// Process data.
    fn process(&self, nonce: &[u8], data: &[u8]) -> Vec<u8>;
}
