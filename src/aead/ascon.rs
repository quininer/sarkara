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
/// # let mut pass = vec![0; Ascon::KEY_LENGTH];
/// # let mut nonce = vec![0; Ascon::NONCE_LENGTH];
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
        assert_eq!(key.len(), Self::KEY_LENGTH);
        Ascon {
            key: Bytes::new(key),
            aad: Vec::new()
        }
    }

    const KEY_LENGTH: usize = 16;
    const TAG_LENGTH: usize = Self::KEY_LENGTH;
    const NONCE_LENGTH: usize = Self::KEY_LENGTH;

    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        assert_eq!(nonce.len(), Self::NONCE_LENGTH);
        let (mut output, tag) = ::ascon::aead_encrypt(&self.key, nonce, data, &self.aad);
        output.extend_from_slice(&tag);
        output
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        assert_eq!(nonce.len(), Self::NONCE_LENGTH);
        if data.len() < Self::TAG_LENGTH { Err(DecryptFail::LengthError)? };
        let (data, tag) = data.split_at(data.len() - Self::TAG_LENGTH);

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
