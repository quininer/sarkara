//! Secret-key Authentication encryption.

use ::aead::{ AeadCipher, DecryptFail };


/// `SecretBox` trait.
///
/// ```
/// # extern crate rand;
/// # #[macro_use] extern crate sarkara;
/// # fn main() {
/// # use sarkara::utils::Bytes;
/// # use sarkara::aead::{ Ascon, AeadCipher };
/// # use sarkara::secretbox::SecretBox;
/// #
/// let key = Bytes::random(Ascon::key_length());
/// let data = rand!(bytes 64);
///
/// let mut ciphertext = Ascon::seal(&key, &data);
/// # assert_eq!(
/// #     ciphertext.len(),
/// #     data.len() + Ascon::tag_length() + Ascon::nonce_length()
/// # );
/// #
/// let plaintext = Ascon::open(&key, &ciphertext).unwrap();
/// assert_eq!(plaintext, &data[..]);
/// #
/// # ciphertext[0] ^= 1;
/// # assert!(Ascon::open(&key, &ciphertext).is_err());
/// # ciphertext[0] ^= 1;
/// # let pos = ciphertext.len();
/// # ciphertext[pos - 1] ^= 1;
/// # assert!(Ascon::open(&key, &ciphertext).is_err());
/// # }
/// ```
pub trait SecretBox: AeadCipher {
    /// Seal SecretBox.
    fn seal(key: &[u8], data: &[u8]) -> Vec<u8> {
        let nonce = rand!(Self::nonce_length());
        let output = Self::new(key)
            .with_aad(&nonce)
            .encrypt(&nonce, data);

        [nonce, output].concat()
    }

    /// Open SecretBox.
    fn open(key: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        if data.len() < Self::tag_length() { Err(DecryptFail::TagLengthError)? };

        let (nonce, data) = data.split_at(Self::nonce_length());
        Self::new(key)
            .with_aad(nonce)
            .decrypt(nonce, data)
    }
}

impl<T> SecretBox for T where T: AeadCipher {}
