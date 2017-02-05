//! Authenticated encryption.
//!
//! Sarkara will use [CAESAR competition](http://competitions.cr.yp.to/caesar.html) winner.

mod general;
mod riv_general;
mod ascon;

use std::{ io, fmt };
use std::error::Error;
pub use self::general::General;
pub use self::riv_general::RivGeneral;
pub use self::ascon::Ascon;


/// Decryption fail.
#[derive(Debug)]
pub enum DecryptFail {
    /// Ciphertext length error.
    LengthError,
    /// Tag authentication fail.
    AuthenticationFail,
    /// Other error.
    Other(io::Error)
}

/// `AeadCipher` trait.
pub trait AeadCipher {
    /// Create a new AeadCipher.
    fn new(key: &[u8]) -> Self where Self: Sized;

    /// Key length.
    fn key_length() -> usize where Self: Sized;
    /// Tag length.
    fn tag_length() -> usize where Self: Sized;
    /// Nonce length.
    fn nonce_length() -> usize where Self: Sized;

    /// Set associated data.
    fn with_aad(&mut self, aad: &[u8]) -> &mut Self;

    /// Encryption.
    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> Vec<u8>;

    /// Decryption
    ///
    /// ## Fail When:
    /// - Ciphertext length error.
    /// - Tag authentication fail.
    /// - Other error.
    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail>;
}

impl fmt::Display for DecryptFail {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Decryption fail: {}", self.description())
    }
}

impl Error for DecryptFail {
    fn description(&self) -> &str {
        match *self {
            DecryptFail::LengthError => "Ciphertext length error.",
            DecryptFail::AuthenticationFail => "Tag authentication fail.",
            DecryptFail::Other(ref err) => err.description()
        }
    }
}

impl From<io::Error> for DecryptFail {
    fn from(err: io::Error) -> DecryptFail {
        DecryptFail::Other(err)
    }
}
