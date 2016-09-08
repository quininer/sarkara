//! Public-key Authenticated encryption.

use std::ops::Deref;
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
/// let data = rand!(rand!(choose 0..1024));
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
    fn seal<K>(pka: &K::PublicKey, data: &[u8])
        -> Vec<u8>
        where
            K: KeyExchange,
            K::Reconciliation: Deref<Target=[u8]>
    {
        let mut key = vec![0; Self::key_length() + Self::nonce_length()];
        let rec = K::exchange(&mut key, pka);
        let (key, nonce) = key.split_at(Self::key_length());

        let mut output = Self::new(key)
            .with_aad(&rec)
            .encrypt(nonce, data);
        output.extend_from_slice(&rec);
        output
    }

    /// Open SecretBox.
    fn open<'a, K>(ska: &K::PrivateKey, data: &'a [u8])
        -> Result<Vec<u8>, DecryptFail>
        where
            K: KeyExchange,
            K::Reconciliation: From<&'a [u8]>
    {
        if data.len() < K::rec_length() { Err(DecryptFail::LengthError)? };

        let mut key = vec![0; Self::key_length() + Self::nonce_length()];
        let (data, rec) = data.split_at(data.len() - K::rec_length());
        K::exchange_from(&mut key, ska, &rec.into());
        let (key, nonce) = key.split_at(Self::key_length());

        Self::new(key)
            .with_aad(rec)
            .decrypt(nonce, data)
    }
}

impl<T> SealedBox for T where T: AeadCipher {}
