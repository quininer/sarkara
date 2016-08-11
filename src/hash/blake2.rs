use blake2_rfc::blake2b::blake2b;
use ::utils::Bytes;
use super::{ GenericHash, Hash };


/// Blake2b.
///
/// # Example(hash)
/// ```
/// use sarkara::hash::{ Blake2b, Hash };
///
/// assert_eq!(
///     Blake2b::default().hash(&[]),
///     &[
///         120, 106, 2, 247, 66, 1, 89, 3,
///         198, 198, 253, 133, 37, 82, 210, 114,
///         145, 47, 71, 64, 225, 88, 71, 97,
///         138, 134, 226, 23, 247, 31, 84, 25,
///         210, 94, 16, 49, 175, 238, 88, 83,
///         19, 137, 100, 68, 147, 78, 176, 75,
///         144, 58, 104, 91, 20, 72, 183, 85,
///         213, 111, 112, 26, 254, 155, 226, 206
///     ][..]
/// );
/// ```
///
/// ## Example(with_size/with_key)
/// ```
/// use sarkara::hash::{ Blake2b, Hash, GenericHash };
///
/// assert_eq!(
///     Blake2b::default()
///         .with_size(16)
///         .with_key(&[5; 16])
///         .hash(&[]),
///     &[
///         148, 148, 166, 38, 121, 23, 19, 81,
///         108, 248, 28, 149, 40, 170, 25, 209
///     ]
/// );
/// ```
pub struct Blake2b {
    outlen: usize,
    key: Bytes
}

impl Default for Blake2b {
    fn default() -> Blake2b {
        Blake2b {
            outlen: Blake2b::digest_length(),
            key: Bytes(Vec::new())
        }
    }
}

impl Hash for Blake2b {
    #[inline] fn digest_length() -> usize { 64 }

    fn hash(&self, data: &[u8]) -> Vec<u8> {
        blake2b(self.outlen, &self.key, data).as_bytes().into()
    }
}

impl GenericHash for Blake2b {
    fn with_size(&mut self, outlen: usize) -> &mut Self {
        self.outlen = outlen;
        self
    }

    fn with_key(&mut self, key: &[u8]) -> &mut Self {
        self.key = Bytes::new(key);
        self
    }
}
