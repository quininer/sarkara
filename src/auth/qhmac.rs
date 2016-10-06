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
///     HMAC::<Blake2b>::new(&[5; 16]).result::<Vec<u8>>(&[]),
///     &[
///         103, 94, 237, 110, 44, 95, 234, 140,
///         231, 34, 21, 54, 134, 161, 118, 37,
///         36, 117, 44, 209, 164, 126, 32, 1,
///         117, 64, 234, 107, 194, 131, 210, 93,
///         95, 127, 126, 222, 45, 114, 152, 82,
///         129, 175, 78, 62, 31, 20, 128, 255,
///         47, 203, 122, 70, 202, 200, 33, 75,
///         253, 132, 234, 116, 220, 81, 39, 182
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
///     HMAC::<Blake2b>::new(&[5; 16])
///         .with_size(16)
///         .with_nonce(&[1; 12])
///         .result::<Vec<u8>>(&[]),
///     &[
///         119, 177, 186, 169, 58, 108, 163, 90,
///         181, 106, 35, 221, 75, 209, 183, 35
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
    #[inline] fn key_length() -> usize { 16 }
    #[inline] fn tag_length() -> usize { H::digest_length() }

    fn new(key: &[u8]) -> Self {
        HMAC {
            key: Bytes::new(key),
            ih: H::default(),
            oh: H::default()
        }
    }

    fn result<T>(&self, data: &[u8]) -> T
        where T: From<Vec<u8>>
    {
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
    #[inline] fn nonce_length() -> usize { 12 }

    fn with_nonce(&mut self, nonce: &[u8]) -> &mut Self {
        self.ih.with_key(nonce);
        self.oh.with_key(nonce);
        self
    }

    fn with_size(&mut self, len: usize) -> &mut Self {
        self.oh.with_size(len);
        self
    }
}
