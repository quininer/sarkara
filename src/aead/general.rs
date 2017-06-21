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
/// # let mut pass = vec![0; HHBB::KEY_LENGTH];
/// # let mut nonce = vec![0; HHBB::NONCE_LENGTH];
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
        assert_eq!(key.len(), Self::KEY_LENGTH);
        let mkey = H::default()
            .with_size(M::KEY_LENGTH)
            .hash::<Bytes>(key);
        General {
            cipher: C::new(key),
            mac: M::new(&mkey),
            hash: PhantomData,
            aad: Vec::new()
        }
    }

    const KEY_LENGTH: usize = C::KEY_LENGTH;
    const TAG_LENGTH: usize = M::TAG_LENGTH;
    const NONCE_LENGTH: usize = C::NONCE_LENGTH;

    #[inline]
    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        assert_eq!(nonce.len(), Self::NONCE_LENGTH);
        let mut nonce_and_aad = Vec::with_capacity(Self::NONCE_LENGTH + self.aad.len());
        nonce_and_aad.extend_from_slice(nonce);
        nonce_and_aad.extend_from_slice(&self.aad);

        let mac_nonce = H::default()
            .with_size(M::NONCE_LENGTH)
            .hash::<Bytes>(&nonce_and_aad);

        let mut output = self.cipher.process(nonce, data);
        let mut tag = self.mac.clone()
            .with_nonce(&mac_nonce)
            .result::<Vec<u8>>(&output);
        output.append(&mut tag);
        output
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        assert_eq!(nonce.len(), Self::NONCE_LENGTH);
        if data.len() < Self::TAG_LENGTH { Err(DecryptFail::LengthError)? };

        let mut nonce_and_aad = Vec::with_capacity(Self::NONCE_LENGTH + self.aad.len());
        nonce_and_aad.extend_from_slice(nonce);
        nonce_and_aad.extend_from_slice(&self.aad);

        let mac_nonce = H::default()
            .with_size(M::NONCE_LENGTH)
            .hash::<Bytes>(&nonce_and_aad);

        let (data, tag) = data.split_at(data.len() - Self::TAG_LENGTH);

        if self.mac.clone().with_nonce(&mac_nonce).verify(data, tag) {
            Ok(self.cipher.process(nonce, data))
        } else {
            Err(DecryptFail::AuthenticationFail)
        }
    }
}
