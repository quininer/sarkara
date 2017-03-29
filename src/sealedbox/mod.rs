//! Public-key Authenticated encryption.

use std::io;
use std::convert::TryFrom;
use rand::{ Rand, Rng };
use seckey::Bytes;
use ::aead::{ AeadCipher, DecryptFail };
use ::kex::KeyExchange;


/// `SealedBox` trait.
///
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// # use rand::{ Rng, thread_rng, ChaChaRng };
/// # use sarkara::aead::{ Ascon, AeadCipher };
/// # use sarkara::kex::{ NewHope, KeyExchange };
/// # use sarkara::sealedbox::SealedBox;
/// #
/// // ...
/// # let mut rng = thread_rng();
/// # let mut data = vec![0; 1024];
/// # rng.fill_bytes(&mut data);
///
/// let (sk, pk) = NewHope::keygen::<ChaChaRng>();
///
/// let mut ciphertext = Ascon::seal::<NewHope, ChaChaRng>(&pk, &data);
/// # assert_eq!(
/// #     ciphertext.len(),
/// #     data.len() + Ascon::tag_length() + NewHope::rec_length()
/// # );
/// let plaintext = Ascon::open::<NewHope>(&sk, &ciphertext).unwrap();
/// assert_eq!(plaintext, data);
/// #
/// # ciphertext[0] ^= 1;
/// # assert!(Ascon::open::<NewHope>(&sk, &ciphertext).is_err());
/// # ciphertext[0] ^= 1;
/// # let pos = ciphertext.len();
/// # ciphertext[pos - 1] ^= 1;
/// # assert!(Ascon::open::<NewHope>(&sk, &ciphertext).is_err());
/// # }
/// ```
pub trait SealedBox {
    /// Seal SecretBox.
    fn seal<K, R>(pka: &K::PublicKey, data: &[u8])
        -> Vec<u8>
        where
            K: KeyExchange,
            K::Reconciliation: Into<Vec<u8>>,
            R: Rand + Rng;

    /// Open SecretBox.
    fn open<K>(ska: &K::PrivateKey, data: &[u8])
        -> Result<Vec<u8>, DecryptFail>
        where
            K: KeyExchange,
            for<'a> K::Reconciliation: TryFrom<&'a [u8], Error=io::Error>;
}

impl<T> SealedBox for T where T: AeadCipher {
    fn seal<K, R>(pka: &K::PublicKey, data: &[u8])
        -> Vec<u8>
        where
            K: KeyExchange,
            K::Reconciliation: Into<Vec<u8>>,
            R: Rand + Rng
    {
        let mut key = Bytes::from(vec![0; Self::key_length() + Self::nonce_length()]);
        let mut rec = K::exchange::<R>(&mut key, pka).into();
        let (key, nonce) = key.split_at(Self::key_length());

        let mut output = Self::new(key)
            .with_aad(&rec)
            .encrypt(nonce, data);
        output.append(&mut rec);
        output
    }

    fn open<K>(ska: &K::PrivateKey, data: &[u8])
        -> Result<Vec<u8>, DecryptFail>
        where
            K: KeyExchange,
            for<'a> K::Reconciliation: TryFrom<&'a [u8], Error=io::Error>
    {
        if data.len() < K::rec_length() { Err(DecryptFail::LengthError)? };

        let mut key = Bytes::from(vec![0; Self::key_length() + Self::nonce_length()]);
        let (data, rec) = data.split_at(data.len() - K::rec_length());
        K::exchange_from(&mut key, ska, &K::Reconciliation::try_from(rec)?);
        let (key, nonce) = key.split_at(Self::key_length());

        Self::new(key)
            .with_aad(rec)
            .decrypt(nonce, data)
    }
}
