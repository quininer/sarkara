use std::marker::PhantomData;
use seckey::Bytes;
use ::stream::StreamCipher;
use ::auth::NonceMac;
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
/// use sarkara::aead::{ RivGeneral, AeadCipher };
/// use sarkara::stream::HC256;
/// use sarkara::auth::HMAC;
/// use sarkara::hash::Blake2b;
///
/// type HRHB = RivGeneral<HC256, HMAC<Blake2b>, Blake2b>;
///
/// // ...
/// # let mut rng = thread_rng();
/// # let mut pass = vec![0; HRHB::key_length()];
/// # let mut nonce = vec![0; HRHB::nonce_length()];
/// # let mut data = vec![0; 1024];
/// # rng.fill_bytes(&mut pass);
/// # rng.fill_bytes(&mut nonce);
/// # rng.fill_bytes(&mut data);
///
/// let ciphertext = HRHB::new(&pass)
///     .with_aad(&nonce)
///     .encrypt(&nonce, &data);
/// let plaintext = HRHB::new(&pass)
///     .with_aad(&nonce)
///     .decrypt(&nonce, &ciphertext)
///     .unwrap();
/// assert_eq!(plaintext, data);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct RivGeneral<C, M, H> {
    cipher: C,
    mac: M,
    hash: PhantomData<H>,
    aad: Vec<u8>
}

impl<C, M, H> AeadCipher for RivGeneral<C, M, H>
    where
        C: StreamCipher,
        M: NonceMac + Clone,
        H: GenericHash
{
    fn new(key: &[u8]) -> Self where Self: Sized {
        let mkey = H::default()
            .with_size(M::key_length())
            .hash::<Bytes>(key);
        let mut mac = M::new(&mkey);
        mac.with_size(C::nonce_length());
        RivGeneral {
            cipher: C::new(key),
            mac: mac,
            hash: PhantomData,
            aad: Vec::new()
        }
    }

    #[inline] fn key_length() -> usize where Self: Sized { C::key_length() }
    #[inline] fn tag_length() -> usize where Self: Sized { C::nonce_length() }
    #[inline] fn nonce_length() -> usize where Self: Sized { M::nonce_length() }

    #[inline]
    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = self.mac.clone();
        mac.with_nonce(nonce);

        let mut aad = self.aad.clone();
        aad.extend_from_slice(data);
        let mut tag = mac.result::<Vec<u8>>(&aad);
        let mut output = self.cipher.process(&tag, data);
        let xorkey = mac.result::<Bytes>(&output);

        for (b, &x) in tag.iter_mut().zip(xorkey.iter()) {
            *b ^= x;
        }

        output.append(&mut tag);
        output
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        if data.len() < Self::tag_length() { Err(DecryptFail::LengthError)? };

        let mut mac = self.mac.clone();
        mac.with_nonce(nonce);

        let (data, tag) = data.split_at(data.len() - Self::tag_length());
        let mut xorkey = mac.result::<Bytes>(data);

        for (b, &x) in xorkey.iter_mut().zip(tag) {
            *b ^= x;
        }

        let output = self.cipher.process(&xorkey, data);
        let mut aad = self.aad.clone();
        aad.extend_from_slice(&output);
        if mac.verify(&aad, &xorkey) {
            Ok(output)
        } else {
            Err(DecryptFail::AuthenticationFail)
        }
    }
}
