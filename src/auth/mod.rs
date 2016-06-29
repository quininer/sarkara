//! Secret-key authentication.
//!
//! Sarkara use [`HMAC`](https://tools.ietf.org/html/rfc2104) nonce variant,
//! in order to better Post-Quantum security.

mod qhmac;

use ::utils::Bytes;
pub use self::qhmac::HMAC;


/// MAC Tag.
pub type Tag = Bytes;

/// `Mac` trait.
pub trait Mac: Default {
    /// Calculate MAC Tag.
    fn result(&self, key: &[u8], data: &[u8]) -> Tag;
    /// Verify MAC Tag.
    fn verify(&self, key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        self.result(key, data) == tag[..]
    }
}

/// `NonceMac` trait.
pub trait NonceMac: Mac {
    /// Set Nonce.
    fn with_nonce(&mut self, nonce: &[u8]) -> &mut Self;

    /// Set MAC code length.
    fn with_size(&mut self, len: usize) -> &mut Self;
}
