use seckey::Bytes;
use ::stream::StreamCipher;
use ::hash::GenericHash;
use super::{ AeadCipher, DecryptFail };


/// General RIV Authenticated Encryption.
///
/// # Example(encrypt/decrypt)
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// use rand::{ Rng, thread_rng };
/// use sarkara::aead::{ GeneralRiv, AeadCipher };
/// use sarkara::stream::HC256;
/// use sarkara::hash::Blake2b;
///
/// type HRB = GeneralRiv<HC256, Blake2b>;
///
/// // ...
/// # let mut rng = thread_rng();
/// # let mut pass = vec![0; HRB::key_length()];
/// # let mut nonce = vec![0; HRB::nonce_length()];
/// # let mut data = vec![0; 1024];
/// # rng.fill_bytes(&mut pass);
/// # rng.fill_bytes(&mut nonce);
/// # rng.fill_bytes(&mut data);
///
/// let ciphertext = HRB::new(&pass)
///     .with_aad(&nonce)
///     .encrypt(&nonce, &data);
/// let plaintext = HRB::new(&pass)
///     .with_aad(&nonce)
///     .decrypt(&nonce, &ciphertext)
///     .unwrap();
/// assert_eq!(plaintext, data);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct GeneralRiv<C, H> {
    cipher: C,
    aad: Vec<u8>,
    hash: H
}

impl<C, H> AeadCipher for GeneralRiv<C, H>
    where
        C: StreamCipher,
        H: GenericHash + Clone
{
    fn new(key: &[u8]) -> Self {
        let mut hash = H::default();
        hash.with_size(C::nonce_length());
        GeneralRiv {
            cipher: C::new(key),
            aad: Vec::new(),
            hash: hash
        }
    }

    #[inline] fn key_length() -> usize { C::key_length() }
    #[inline] fn tag_length() -> usize { C::nonce_length() }
    #[inline] fn nonce_length() -> usize { C::nonce_length() }

    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let mut hash = self.hash.clone();

        hash.with_key(nonce);

        let mut aad = self.aad.clone();
        aad.extend_from_slice(data);
        let mut nonce = hash.hash::<Vec<u8>>(&aad);
        let mut output = self.cipher.process(&nonce, data);
        let xorkey = hash.hash::<Bytes>(&output);

        for (b, &x) in nonce.iter_mut().zip(xorkey.iter()) {
            *b ^= x;
        }

        output.append(&mut nonce);
        output
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        if data.len() < Self::tag_length() { Err(DecryptFail::LengthError)? };

        let mut hash = self.hash.clone();
        hash.with_key(nonce);

        let (data, tag) = data.split_at(data.len() - Self::tag_length());
        let mut nonce = hash.hash::<Bytes>(data);

        for (b, &x) in nonce.iter_mut().zip(tag) {
            *b ^= x;
        }

        let output = self.cipher.process(&nonce, data);
        let mut aad = self.aad.clone();
        aad.extend_from_slice(&output);
        if hash.hash::<Bytes>(&aad) == nonce {
            Ok(output)
        } else {
            Err(DecryptFail::AuthenticationFail)
        }
    }
}
