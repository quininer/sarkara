//! Password Hashing.
//!
//! Sarkara use [`Argon2i`](https://github.com/P-H-C/phc-winner-argon2),
//! it based on [`Blake2`](https://blake2.net/) hashing function,
//! is [Password Hashing Competition](https://password-hashing.net/) winner.


mod argon2;

use std::fmt;
use std::error::Error;
use ::utils::Bytes;
pub use self::argon2::{
    Argon2i,
    OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE,
    OPSLIMIT_MODERATE, MEMLIMIT_MODERATE,
    OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE
};


/// Hashed Password.
pub type Key = Bytes;

/// Key derivation error.
#[derive(Clone, Debug)]
pub enum KeyDerivationFail {
    /// parameter error.
    ParameterError(String),
    /// Output length too short.
    OutLenTooShort,
    /// Output length too long.
    OutLenTooLong,
    /// Salt too short.
    SaltTooShort,
    /// Salt too long.
    SaltTooLong
}

/// `KeyDerive` trait.
pub trait KeyDerive: Default {
    /// Generate a hashed password.
    ///
    /// ## Fail When:
    /// * Param Error, see [`ParamErr`](../../argon2rs/enum.ParamErr.html)
    fn pwhash(&self, password: &[u8]) -> Result<Key, KeyDerivationFail> {
        self.derive(password, &rand!(bytes 8))
    }

    /// Set output length.
    fn with_size(&mut self, len: usize) -> &mut Self;
    /// Set key.
    fn with_key(&mut self, key: &[u8]) -> &mut Self;
    /// Set associated data.
    fn with_aad(&mut self, aad: &[u8]) -> &mut Self;
    /// Set opslimit parameter.
    fn with_opslimit(&mut self, opslimit: u32) -> &mut Self;
    /// Set memlimit parameter.
    fn with_memlimit(&mut self, memlimit: u32) -> &mut Self;

    /// Derive key.
    ///
    /// ## Fail When:
    /// * Param Error, see [`ParamErr`](../../argon2rs/enum.ParamErr.html)
    fn derive(&self, password: &[u8], salt: &[u8]) -> Result<Key, KeyDerivationFail>;
}

/// `KeyVerify` trait.
pub trait KeyVerify: KeyDerive {
    /// Verify password hash.
    ///
    /// ## Fail When:
    /// * Param Error, see [`ParamErr`](../../argon2rs/enum.ParamErr.html)
    fn verify(&self, password: &[u8], salt: &[u8], hash: &[u8]) -> Result<bool, KeyDerivationFail> {
        Ok(self.derive(password, salt)? == hash[..])
    }
}

impl<T> KeyVerify for T where T: KeyDerive {}

impl fmt::Display for KeyDerivationFail {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl Error for KeyDerivationFail {
    fn description(&self) -> &str {
        match *self {
            KeyDerivationFail::ParameterError(ref string) => string,
            KeyDerivationFail::OutLenTooShort => "Output length too short.",
            KeyDerivationFail::OutLenTooLong => "Output length too long.",
            KeyDerivationFail::SaltTooShort => "Salt too short.",
            KeyDerivationFail::SaltTooLong => "Salt too long."
        }
    }
}
