//! Secret-key encryption.
//!
//! Sarkara use [`hc256`](http://www.ecrypt.eu.org/stream/hcpf.html),
//! it is one of [`eSTREAM`](http://www.ecrypt.eu.org/stream/) portfolio,
//! have good design and performance.

pub mod hc256;

pub use self::hc256::HC256;


/// `StreamCipher` trait.
pub trait StreamCipher {
    /// Create a new StreamCipher.
    ///
    /// ## Panic When:
    /// - key length not equal `StreamCipher::KEY_LENGTH`.
    fn new(key: &[u8]) -> Self where Self: Sized;

    /// Key length.
    const KEY_LENGTH: usize;
    /// Nonce length.
    const NONCE_LENGTH: usize;

    /// Process data.
    ///
    /// ## Panic When:
    /// - nonce length not equal `StreamCipher::NONCE_LENGTH`.
    fn process(&self, nonce: &[u8], data: &[u8]) -> Vec<u8>;
}
