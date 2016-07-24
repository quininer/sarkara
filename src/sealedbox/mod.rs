//! Public-key Authenticated encryption.

use ::aead::{ AeadCipher, DecryptFail };
use ::kex::KeyExchange;


/// `SealedBox` trait.
///
/// ```
/// # extern crate rand;
/// # #[macro_use] extern crate sarkara;
/// # fn main() {
/// # use sarkara::aead::{ Ascon, AeadCipher };
/// # use sarkara::kex::{ NewHope, KeyExchange };
/// # use sarkara::sealedbox::SealedBox;
/// #
/// let data = rand!(bytes 64);
/// let (sk, pk) = NewHope::keygen();
///
/// let mut ciphertext = Ascon::seal::<NewHope>(&pk, &data);
/// # assert_eq!(
/// #     ciphertext.len(),
/// #     data.len() + Ascon::tag_length() + NewHope::rec_length()
/// # );
/// let plaintext = Ascon::open::<NewHope>(&sk, &ciphertext).unwrap();
/// assert_eq!(plaintext, &data[..]);
/// #
/// # ciphertext[0] ^= 1;
/// # assert!(Ascon::open::<NewHope>(&sk, &ciphertext).is_err());
/// # ciphertext[0] ^= 1;
/// # let pos = ciphertext.len();
/// # ciphertext[pos - 1] ^= 1;
/// # assert!(Ascon::open::<NewHope>(&sk, &ciphertext).is_err());
/// # }
/// ```
pub trait SealedBox: AeadCipher {
    /// Seal SecretBox.
    fn seal<K: KeyExchange>(pka: &[u8], data: &[u8]) -> Vec<u8> {
        let mut key = vec![0; Self::key_length() + Self::nonce_length()];
        let rec = K::exchange(&mut key, pka);

        let mut output = Self::new(&key[..Self::key_length()])
            .with_aad(&rec)
            .encrypt(&key[Self::key_length()..], data);
        output.extend_from_slice(&rec);
        output
    }

    /// Open SecretBox.
    fn open<K: KeyExchange>(ska: &K::PrivateKey, data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        let mut key = vec![0; Self::key_length() + Self::nonce_length()];
        let (data, rec) = data.split_at(data.len() - K::rec_length());
        K::exchange_from(&mut key, ska, rec);

        Self::new(&key[..Self::key_length()])
            .with_aad(rec)
            .decrypt(&key[Self::key_length()..], data)
    }
}

impl<T> SealedBox for T where T: AeadCipher {}
