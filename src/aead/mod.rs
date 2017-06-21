//! Authenticated encryption.
//!
//! Sarkara will use [CAESAR competition](http://competitions.cr.yp.to/caesar.html) winner.

pub mod general;
pub mod riv_general;
pub mod ascon;

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
    ///
    /// ## Panic When:
    /// - key length not equal `AeadCipher::KEY_LENGTH`.
    fn new(key: &[u8]) -> Self where Self: Sized;


    /// Key length.
    const KEY_LENGTH: usize;
    /// Tag length.
    const TAG_LENGTH: usize;
    /// Nonce length.
    const NONCE_LENGTH: usize;

    /// Set associated data.
    fn with_aad(&mut self, aad: &[u8]) -> &mut Self;

    /// Encryption.
    ///
    /// ## Panic When:
    /// - nonce length not equal `AeadCipher::NONCE_LENGTH`.
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

    fn cause(&self) -> Option<&Error> {
        match *self {
            DecryptFail::Other(ref err) => Some(err),
            _ => None
        }
    }
}

impl From<io::Error> for DecryptFail {
    fn from(err: io::Error) -> DecryptFail {
        DecryptFail::Other(err)
    }
}
