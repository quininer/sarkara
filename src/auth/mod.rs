//! Secret-key authentication.
//!
//! Sarkara use [`HMAC`](https://tools.ietf.org/html/rfc2104) nonce variant,
//! in order to better Post-Quantum security.

mod qhmac;

pub use self::qhmac::HMAC;


/// `Mac` trait.
pub trait Mac {
    /// MAC tag.
    type Tag;

    /// Key length.
    fn key_length() -> usize;
    /// Tag length.
    fn tag_length() -> usize;

    /// Create a new MAC.
    fn new(key: &[u8]) -> Self;

    /// Calculate MAC Tag.
    fn result(&self, data: &[u8]) -> Self::Tag;
    /// Verify MAC Tag.
    fn verify(&self, data: &[u8], tag: &[u8]) -> bool;
}

/// `NonceMac` trait.
pub trait NonceMac: Mac {
    /// Nonce length
    fn nonce_length() -> usize;

    /// Set Nonce.
    fn with_nonce(&mut self, nonce: &[u8]) -> &mut Self;
    /// Set MAC code length.
    fn with_size(&mut self, len: usize) -> &mut Self;
}
