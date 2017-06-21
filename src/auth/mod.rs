//! Secret-key authentication.
//!
//! Sarkara use [`HMAC`](https://tools.ietf.org/html/rfc2104) nonce variant,
//! in order to better Post-Quantum security.

pub mod qhmac;

use seckey::Bytes;
pub use self::qhmac::HMAC;


/// `Mac` trait.
pub trait Mac {
    /// Key length.
    const KEY_LENGTH: usize;
    /// Tag length.
    const TAG_LENGTH: usize;

    /// Create a new MAC.
    ///
    /// ## Panic When:
    /// - key length not equal `Mac::KEY_LENGTH`.
    fn new(key: &[u8]) -> Self where Self: Sized;

    /// Calculate MAC Tag.
    fn result<T>(&self, data: &[u8]) -> T where T: From<Vec<u8>>;

    /// Verify MAC Tag.
    fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        self.result::<Bytes>(data) == tag
    }
}

/// `NonceMac` trait.
pub trait NonceMac: Mac {
    /// Nonce length
    const NONCE_LENGTH: usize;

    /// Set Nonce.
    ///
    /// ## Panic When:
    /// - nonce length not equal `NonceMac::NONCE_LENGTH`.
    fn with_nonce(&mut self, nonce: &[u8]) -> &mut Self;
    /// Set MAC output length.
    fn with_size(&mut self, len: usize) -> &mut Self;
}
