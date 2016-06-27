//! Secret-key encryption.
//!
//! Sarkara use [`HC-128`](http://www.ecrypt.eu.org/stream/hcpf.html),
//! it is one of [`eSTREAM`](http://www.ecrypt.eu.org/stream/) portfolio,
//! have good design and performance.

mod hc128;

pub use self::hc128::HC128;


/// `StreamCipher` trait.
pub trait StreamCipher {
    /// Create a new StreamCipher.
    fn new(key: &[u8]) -> Self;

    /// Process data.
    fn process(&self, nonce: &[u8], data: &[u8]) -> Vec<u8>;
}
