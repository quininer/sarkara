use ::stream::StreamCipher;
use ::auth::NonceMac;
use super::{ AeadCipher, DecryptFail };


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
/// type HHBCipher = General<HC256, HMAC<Blake2b>>;
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
pub struct General<C, M> {
    cipher: C,
    mac: M,
    aad: Vec<u8>
}

impl<C, M> AeadCipher for General<C, M> where
    C: StreamCipher,
    M: NonceMac
{
    fn new(key: &[u8]) -> Self {
        let (ckey, mkey) = key.split_at(C::key_length());
        General {
            cipher: C::new(ckey),
            mac: M::new(mkey),
            aad: Vec::new()
        }
    }

    #[inline] fn key_length() -> usize { C::key_length() + M::key_length() }
    #[inline] fn tag_length() -> usize { M::tag_length() }
    #[inline] fn nonce_length() -> usize { C::nonce_length() + M::nonce_length() }

    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn encrypt(&mut self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let (cn, mn) = nonce.split_at(C::nonce_length());
        let mut output = self.cipher.process(cn, data);
        let mut aad = self.aad.clone();
        aad.extend_from_slice(&output);

        let mut tag = self.mac
            .with_nonce(mn)
            .result::<Vec<u8>>(&aad);
        output.append(&mut tag);
        output
    }

    fn decrypt(&mut self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        if data.len() < Self::tag_length() { Err(DecryptFail::LengthError)? };

        let (cn, mn) = nonce.split_at(C::nonce_length());
        let (data, tag) = data.split_at(data.len() - Self::tag_length());
        let mut aad = self.aad.clone();
        aad.extend_from_slice(data);

        if self.mac.with_nonce(mn).verify(&aad, tag) {
            Ok(self.cipher.process(cn, data))
        } else {
            Err(DecryptFail::AuthenticationFail)
        }
    }
}
