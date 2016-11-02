use ::stream::StreamCipher;
use ::auth::NonceMac;
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
/// type HHB = General<HC256, HMAC<Blake2b>>;
///
/// // ...
/// # let mut rng = thread_rng();
/// # let mut pass = vec![0; HHB::key_length()];
/// # let mut nonce = vec![0; HHB::nonce_length()];
/// # let mut data = vec![0; 1024];
/// # rng.fill_bytes(&mut pass);
/// # rng.fill_bytes(&mut nonce);
/// # rng.fill_bytes(&mut data);
///
/// let ciphertext = HHB::new(&pass)
///     .with_aad(&nonce)
///     .encrypt(&nonce, &data);
/// let plaintext = HHB::new(&pass)
///     .with_aad(&nonce)
///     .decrypt(&nonce, &ciphertext)
///     .unwrap();
/// assert_eq!(plaintext, data);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct General<C, M> {
    cipher: C,
    mac: M,
    aad: Vec<u8>
}

impl<C, M> AeadCipher for General<C, M>
    where
        C: StreamCipher,
        M: NonceMac + Clone
{
    fn new(key: &[u8]) -> Self {
        General {
            cipher: C::new(key),
            mac: M::new(key),
            aad: Vec::new()
        }
    }

    #[inline] fn key_length() -> usize { C::key_length() }
    #[inline] fn tag_length() -> usize { M::tag_length() }
    #[inline] fn nonce_length() -> usize { C::nonce_length() }

    #[inline]
    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let mut output = self.cipher.process(nonce, data);

        let mut aad = self.aad.clone();
        aad.extend_from_slice(&output);
        let mut tag = self.mac.clone()
            .with_nonce(nonce)
            .result::<Vec<u8>>(&aad);
        output.append(&mut tag);
        output
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        if data.len() < Self::tag_length() { Err(DecryptFail::LengthError)? };

        let (data, tag) = data.split_at(data.len() - Self::tag_length());

        let mut aad = self.aad.clone();
        aad.extend_from_slice(data);
        if self.mac.clone().with_nonce(nonce).verify(&aad, tag) {
            Ok(self.cipher.process(nonce, data))
        } else {
            Err(DecryptFail::AuthenticationFail)
        }
    }
}
