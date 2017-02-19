//! [ascon](http://ascon.iaik.tugraz.at/).

use seckey::Bytes;
use super::{ AeadCipher, DecryptFail };


/// Ascon.
///
/// # Example(encrypt/decrypt)
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// use rand::{ Rng, thread_rng };
/// use sarkara::aead::{ Ascon, AeadCipher };
///
/// // ...
/// # let mut rng = thread_rng();
/// # let mut pass = vec![0; Ascon::key_length()];
/// # let mut nonce = vec![0; Ascon::nonce_length()];
/// # let mut data = vec![0; 1024];
/// # rng.fill_bytes(&mut pass);
/// # rng.fill_bytes(&mut nonce);
/// # rng.fill_bytes(&mut data);
///
/// let ciphertext = Ascon::new(&pass)
///     .with_aad(&nonce)
///     .encrypt(&nonce, &data);
/// let plaintext = Ascon::new(&pass)
///     .with_aad(&nonce)
///     .decrypt(&nonce, &ciphertext)
///     .unwrap();
/// assert_eq!(plaintext, data);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Ascon {
    key: Bytes,
    aad: Vec<u8>
}

impl AeadCipher for Ascon {
    fn new(key: &[u8]) -> Self where Self: Sized {
        debug_assert_eq!(key.len(), Self::key_length());
        Ascon {
            key: Bytes::new(key),
            aad: Vec::new()
        }
    }

    #[inline] fn key_length() -> usize where Self: Sized { 16 }
    #[inline] fn tag_length() -> usize where Self: Sized { Self::key_length() }
    #[inline] fn nonce_length() -> usize where Self: Sized { Self::key_length() }

    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        debug_assert_eq!(nonce.len(), Self::nonce_length());
        let (mut output, tag) = ::ascon::aead_encrypt(&self.key, nonce, data, &self.aad);
        output.extend_from_slice(&tag);
        output
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        debug_assert_eq!(nonce.len(), Self::nonce_length());
        if data.len() < Self::tag_length() { Err(DecryptFail::LengthError)? };
        let (data, tag) = data.split_at(data.len() - Self::tag_length());

        ::ascon::aead_decrypt(&self.key, nonce, data, &self.aad, tag)
            .map_err(|err| err.into())
    }
}

impl From<::ascon::DecryptFail> for DecryptFail {
    fn from(err: ::ascon::DecryptFail) -> DecryptFail {
        match err {
            ::ascon::DecryptFail::TagLengthError => DecryptFail::LengthError,
            ::ascon::DecryptFail::AuthenticationFail => DecryptFail::AuthenticationFail
        }
    }
}
