use ::stream::StreamCipher;
use ::auth::NonceMac;
use ::hash::GenericHash;
use super::{ AeadCipher, DecryptFail };
use std::marker::PhantomData;


/// General Authenticated Encryption.
///
/// # Example(encrypt/decrypt)
/// ```
/// # extern crate rand;
/// # #[macro_use] extern crate sarkara;
/// # fn main() {
/// use sarkara::aead::{ General, AeadCipher };
/// use sarkara::stream::HC256;
/// use sarkara::auth::HMAC;
/// use sarkara::hash::Blake2b;
///
/// type HHBCipher = General<HC256, HMAC<Blake2b>, Blake2b>;
///
/// let (pass, nonce) = (
///     rand!(HHBCipher::key_length()),
///     rand!(HHBCipher::nonce_length())
/// );
/// let data = rand!(rand!(choose 0..1024));
/// let ciphertext = HHBCipher::new(&pass)
///     .with_aad(&nonce)
///     .encrypt(&nonce, &data);
/// let plaintext = HHBCipher::new(&pass)
///     .with_aad(&nonce)
///     .decrypt(&nonce, &ciphertext)
///     .unwrap();
/// assert_eq!(plaintext, &data[..]);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct General<C, M, H> {
    cipher: C,
    mac: M,
    aad: Vec<u8>,
    _ext: PhantomData<H>
}

impl<C, M, H> AeadCipher for General<C, M, H>
    where
        C: StreamCipher,
        M: NonceMac,
        H: GenericHash
{
    fn new(key: &[u8]) -> Self {
        let mkey = H::default()
            .with_size(M::key_length())
            .hash::<Vec<u8>>(key);
        General {
            cipher: C::new(key),
            mac: M::new(&mkey),
            aad: Vec::new(),
            _ext: PhantomData
        }
    }

    #[inline] fn key_length() -> usize { C::key_length() }
    #[inline] fn tag_length() -> usize { M::tag_length() }
    #[inline] fn nonce_length() -> usize { C::nonce_length() }

    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn encrypt(&mut self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let mnonce = H::default()
            .with_size(M::nonce_length())
            .hash::<Vec<u8>>(nonce);
        let mut output = self.cipher.process(nonce, data);
        let mut aad = self.aad.clone();
        aad.extend_from_slice(&output);

        let mut tag = self.mac
            .with_nonce(&mnonce)
            .result::<Vec<u8>>(&aad);
        output.append(&mut tag);
        output
    }

    fn decrypt(&mut self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        if data.len() < Self::tag_length() { Err(DecryptFail::LengthError)? };

        let mnonce = H::default()
            .with_size(M::nonce_length())
            .hash::<Vec<u8>>(nonce);
        let (data, tag) = data.split_at(data.len() - Self::tag_length());
        let mut aad = self.aad.clone();
        aad.extend_from_slice(data);

        if self.mac.with_nonce(&mnonce).verify(&aad, tag) {
            Ok(self.cipher.process(nonce, data))
        } else {
            Err(DecryptFail::AuthenticationFail)
        }
    }
}
