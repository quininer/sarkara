use seckey::Bytes;
use ::hash::{ Hash, GenericHash };
use super::{ Mac, NonceMac };


/// HMAC, nonce variant.
///
/// # Definition:
/// `H(nonce, (K xor opad) || H(nonce, (K xor ipad) || text))`
///
/// # Example(result)
/// ```
/// use sarkara::auth::{ HMAC, Mac };
/// use sarkara::hash::Blake2b;
///
/// assert_eq!(
///     HMAC::<Blake2b>::new(&[5; 32]).result::<Vec<u8>>(&[]),
///     &[
///         194, 146, 2, 54, 145, 176, 76, 56,
///         71, 226, 163, 78, 115, 255, 194, 236,
///         97, 247, 113, 31, 27, 97, 130, 65,
///         159, 245, 153, 168, 253, 62, 35, 36,
///         21, 99, 142, 146, 89, 45, 34, 157,
///         59, 93, 191, 9, 78, 149, 97, 232,
///         59, 119, 148, 57, 70, 50, 233, 84,
///         22, 255, 81, 102, 20, 137, 181, 124
///     ][..]
/// );
/// ```
///
/// # Example(with_size/with_nonce)
/// ```
/// use sarkara::auth::{ HMAC, Mac, NonceMac };
/// use sarkara::hash::Blake2b;
///
/// assert_eq!(
///     HMAC::<Blake2b>::new(&[5; 32])
///         .with_size(16)
///         .with_nonce(&[1; 32])
///         .result::<Vec<u8>>(&[]),
///     &[
///         179, 8, 125, 182, 165, 35, 131, 1,
///         242, 7, 138, 85, 27, 77, 214, 216
///     ]
/// );
/// ```
#[derive(Debug, Clone)]
pub struct HMAC<H> {
    key: Bytes,
    ih: H,
    oh: H
}

impl<H> Mac for HMAC<H> where H: Hash {
    #[inline] fn key_length() -> usize where Self: Sized { 32 }
    #[inline] fn tag_length() -> usize where Self: Sized { H::digest_length() }

    fn new(key: &[u8]) -> Self where Self: Sized {
        debug_assert_eq!(key.len(), Self::key_length());
        HMAC {
            key: Bytes::new(key),
            ih: H::default(),
            oh: H::default()
        }
    }

    fn result<T>(&self, data: &[u8]) -> T  where T: From<Vec<u8>> {
        let mut ipad = vec![0x36; 64];
        let mut opad = vec![0x5c; 64];

        for (i, &b) in self.key.iter().take(64).enumerate() {
            ipad[i] ^= b;
            opad[i] ^= b;
        }

        ipad.extend_from_slice(data);
        opad.append(&mut self.ih.hash::<Vec<u8>>(&ipad));

        self.oh.hash(&opad)
    }
}

impl<H> NonceMac for HMAC<H> where H: GenericHash {
    #[inline] fn nonce_length() -> usize where Self: Sized { 32 }

    #[inline]
    fn with_nonce(&mut self, nonce: &[u8]) -> &mut Self {
        debug_assert_eq!(nonce.len(), Self::nonce_length());
        self.ih.with_key(nonce);
        self.oh.with_key(nonce);
        self
    }

    #[inline]
    fn with_size(&mut self, len: usize) -> &mut Self {
        self.oh.with_size(len);
        self
    }
}
