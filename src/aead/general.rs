//! General Authenticated Encryption.

use std::marker::PhantomData;
use seckey::Bytes;
use ::stream::StreamCipher;
use ::auth::NonceMac;
use ::hash::GenericHash;
use super::{ AeadCipher, DecryptFail };


/// General Authenticated Encryption.
///
/// # Example(encrypt/decrypt)
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// use rand::{ Rng, thread_rng };
/// use sarkara::aead::{ General, AeadCipher };
/// use sarkara::stream::HC256;
/// use sarkara::auth::HMAC;
/// use sarkara::hash::Blake2b;
///
/// type HHBB = General<HC256, HMAC<Blake2b>, Blake2b>;
///
/// // ...
/// # let mut rng = thread_rng();
/// # let mut pass = vec![0; HHBB::key_length()];
/// # let mut nonce = vec![0; HHBB::nonce_length()];
/// # let mut data = vec![0; 1024];
/// # rng.fill_bytes(&mut pass);
/// # rng.fill_bytes(&mut nonce);
/// # rng.fill_bytes(&mut data);
///
/// let ciphertext = HHBB::new(&pass)
///     .with_aad(&nonce)
///     .encrypt(&nonce, &data);
/// let plaintext = HHBB::new(&pass)
///     .with_aad(&nonce)
///     .decrypt(&nonce, &ciphertext)
///     .unwrap();
/// assert_eq!(plaintext, data);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct General<C, M, H> {
    cipher: C,
    mac: M,
    hash: PhantomData<H>,
    aad: Vec<u8>
}

impl<C, M, H> AeadCipher for General<C, M, H>
    where
        C: StreamCipher,
        M: NonceMac + Clone,
        H: GenericHash
{
    fn new(key: &[u8]) -> Self where Self: Sized {
        assert_eq!(key.len(), Self::key_length());
        let mkey = H::default()
            .with_size(M::key_length())
            .hash::<Bytes>(key);
        General {
            cipher: C::new(key),
            mac: M::new(&mkey),
            hash: PhantomData,
            aad: Vec::new()
        }
    }

    #[inline] fn key_length() -> usize where Self: Sized { C::key_length() }
    #[inline] fn tag_length() -> usize where Self: Sized { M::tag_length() }
    #[inline] fn nonce_length() -> usize where Self: Sized { C::nonce_length() }

    #[inline]
    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        assert_eq!(nonce.len(), Self::nonce_length());
        let mut nonce_and_aad = Vec::with_capacity(Self::nonce_length() + self.aad.len());
        nonce_and_aad.extend_from_slice(nonce);
        nonce_and_aad.extend_from_slice(&self.aad);

        let mac_nonce = H::default()
            .with_size(M::nonce_length())
            .hash::<Bytes>(&nonce_and_aad);

        let mut output = self.cipher.process(nonce, data);
        let mut tag = self.mac.clone()
            .with_nonce(&mac_nonce)
            .result::<Vec<u8>>(&output);
        output.append(&mut tag);
        output
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        assert_eq!(nonce.len(), Self::nonce_length());
        if data.len() < Self::tag_length() { Err(DecryptFail::LengthError)? };

        let mut nonce_and_aad = Vec::with_capacity(Self::nonce_length() + self.aad.len());
        nonce_and_aad.extend_from_slice(nonce);
        nonce_and_aad.extend_from_slice(&self.aad);

        let mac_nonce = H::default()
            .with_size(M::nonce_length())
            .hash::<Bytes>(&nonce_and_aad);

        let (data, tag) = data.split_at(data.len() - Self::tag_length());

        if self.mac.clone().with_nonce(&mac_nonce).verify(&data, tag) {
            Ok(self.cipher.process(nonce, data))
        } else {
            Err(DecryptFail::AuthenticationFail)
        }
    }
}
