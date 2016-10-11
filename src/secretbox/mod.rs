//! Secret-key Authenticated encryption.

use rand::OsRng;
use ::aead::{ AeadCipher, DecryptFail };
use ::utils::GenNonce;


/// `SecretBox` trait.
///
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// # use rand::{ Rng, thread_rng };
/// # use sarkara::aead::{ Ascon, AeadCipher };
/// # use sarkara::secretbox::SecretBox;
/// #
/// let mut rng = thread_rng();
/// let mut key = vec![0; Ascon::key_length()];
/// let mut data = vec![0; 1024];
/// rng.fill_bytes(&mut key);
/// rng.fill_bytes(&mut data);
///
/// let mut ciphertext = Ascon::seal(&key, &data);
/// # assert_eq!(
/// #     ciphertext.len(),
/// #     data.len() + Ascon::tag_length() + Ascon::nonce_length()
/// # );
/// #
/// let plaintext = Ascon::open(&key, &ciphertext).unwrap();
/// assert_eq!(plaintext, data);
/// #
/// # ciphertext[0] ^= 1;
/// # assert!(Ascon::open(&key, &ciphertext).is_err());
/// # ciphertext[0] ^= 1;
/// # let pos = ciphertext.len();
/// # ciphertext[pos - 1] ^= 1;
/// # assert!(Ascon::open(&key, &ciphertext).is_err());
/// # }
/// ```
pub trait SecretBox {
    /// Seal SecretBox.
    #[inline]
    fn seal(key: &[u8], data: &[u8]) -> Vec<u8> {
        Self::seal_with_nonce(&mut OsRng::new().unwrap(), key, data)
    }

    /// Seal SecretBox with Nonce.
    fn seal_with_nonce(rng: &mut GenNonce, key: &[u8], data: &[u8]) -> Vec<u8>;

    /// Open SecretBox.
    fn open(key: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail>;
}

impl<T> SecretBox for T where T: AeadCipher {
    fn seal_with_nonce(rng: &mut GenNonce, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut nonce = vec![0; Self::nonce_length()];
        rng.fill(&mut nonce);
        let output = Self::new(key)
            .with_aad(&nonce)
            .encrypt(&nonce, data);

        [nonce, output].concat()
    }

    fn open(key: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        if data.len() < Self::tag_length() + Self::nonce_length() {
            Err(DecryptFail::LengthError)?
        };

        let (nonce, data) = data.split_at(Self::nonce_length());
        Self::new(key)
            .with_aad(nonce)
            .decrypt(nonce, data)
    }
}
