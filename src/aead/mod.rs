//! Authenticated encryption.
//!
//! Sarkara will use [CAESAR competition](http://competitions.cr.yp.to/caesar.html) winner.

mod general;
mod general_riv;
mod ascon;

use std::{ io, fmt };
use std::error::Error;
pub use self::general::General;
pub use self::general_riv::GeneralRiv;
pub use self::ascon::Ascon;


/// Decryption fail.
#[derive(Debug)]
pub enum DecryptFail {
    /// Ciphertext length error.
    LengthError,
    /// Tag authentication fail.
    AuthenticationFail,
    /// Tag authentication fail, but
    AuthenticationFailBut(Vec<u8>),
    /// Other error.
    Other(io::Error)
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
    /// - Ciphertext length error.
    /// - Tag authentication fail.
    /// - Other error.
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
            DecryptFail::LengthError => "Ciphertext length error.",
            DecryptFail::AuthenticationFail => "Tag authentication fail.",
            DecryptFail::AuthenticationFailBut(_) => "Tag authentication fail, but output.",
            DecryptFail::Other(ref err) => err.description()
        }
    }
}

impl From<io::Error> for DecryptFail {
    fn from(err: io::Error) -> DecryptFail {
        DecryptFail::Other(err)
    }
}
