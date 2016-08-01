//! Secret-key Authenticated encryption.
//!
//! Sarkara will use [CAESAR competition](http://competitions.cr.yp.to/caesar.html) winner.

mod general;
mod ascon;

use std::fmt;
use std::error::Error;
pub use self::general::General;
pub use self::ascon::Ascon;


/// Decryption fail.
#[derive(Clone, Debug)]
pub enum DecryptFail {
    /// Tag length error.
    TagLengthError,
    /// Tag authentication fail.
    AuthenticationFail
}

/// `AeadCipher` trait.
pub trait AeadCipher {
    /// Create a new AeadCipher.
    fn new(key: &[u8]) -> Self;

    /// Key length.
    fn key_length() -> usize;
    /// Tag length.
    fn tag_length() -> usize;
    /// Nonce length.
    fn nonce_length() -> usize;

    /// Set associated data.
    fn with_aad(&mut self, aad: &[u8]) -> &mut Self;

    /// Encryption.
    fn encrypt(&mut self, nonce: &[u8], data: &[u8]) -> Vec<u8>;

    /// Decryption
    ///
    /// ## Fail When:
    /// - Tag length error.
    /// - Tag authentication fail.
    fn decrypt(&mut self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail>;
}

impl fmt::Display for DecryptFail {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl Error for DecryptFail {
    fn description(&self) -> &str {
        match *self {
            DecryptFail::TagLengthError => "Tag length error.",
            DecryptFail::AuthenticationFail => "Tag authentication fail."
        }
    }
}
