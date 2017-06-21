//! General RIV Authenticated Encryption.

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
/// # let mut pass = vec![0; HRHB::KEY_LENGTH];
/// # let mut nonce = vec![0; HRHB::NONCE_LENGTH];
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
        assert_eq!(key.len(), Self::KEY_LENGTH);
        let mac_key = H::default()
            .with_size(M::KEY_LENGTH)
            .hash::<Bytes>(key);
        let mut mac = M::new(&mac_key);
        mac.with_size(C::NONCE_LENGTH);
        RivGeneral {
            cipher: C::new(key),
            mac: mac,
            hash: PhantomData,
            aad: Vec::new()
        }
    }

    const KEY_LENGTH: usize = C::KEY_LENGTH;
    const TAG_LENGTH: usize = C::NONCE_LENGTH;
    const NONCE_LENGTH: usize = M::NONCE_LENGTH;

    #[inline]
    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        assert_eq!(nonce.len(), Self::NONCE_LENGTH);
        let mut mac = self.mac.clone();
        mac.with_nonce(nonce);

        let mut aad_and_data = Vec::with_capacity(self.aad.len() + data.len());
        aad_and_data.extend_from_slice(&self.aad);
        aad_and_data.extend_from_slice(data);
        let mut tag = mac.result::<Vec<u8>>(&aad_and_data);
        let mut output = self.cipher.process(&tag, data);
        let xorkey = mac.result::<Bytes>(&output);

        for (b, &x) in tag.iter_mut().zip(xorkey.iter()) {
            *b ^= x;
        }

        output.append(&mut tag);
        output
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        assert_eq!(nonce.len(), Self::NONCE_LENGTH);
        if data.len() < Self::TAG_LENGTH { Err(DecryptFail::LengthError)? };

        let mut mac = self.mac.clone();
        mac.with_nonce(nonce);

        let (data, tag) = data.split_at(data.len() - Self::TAG_LENGTH);
        let mut xorkey = mac.result::<Bytes>(data);

        for (b, &x) in xorkey.iter_mut().zip(tag) {
            *b ^= x;
        }

        let output = self.cipher.process(&xorkey, data);
        let mut aad_and_data = Vec::with_capacity(self.aad.len() + output.len());
        aad_and_data.extend_from_slice(&self.aad);
        aad_and_data.extend_from_slice(&output);
        if mac.verify(&aad_and_data, &xorkey) {
            Ok(output)
        } else {
            Err(DecryptFail::AuthenticationFail)
        }
    }
}
