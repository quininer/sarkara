use std::ops::{ Deref, DerefMut };
use memsec::{ memzero, memcmp };


/// Temporary Bytes.
///
/// ```
/// use sarkara::utils::{ SecBytes, Bytes };
///
/// let secbytes = SecBytes::new(&[1; 8]).unwrap();
/// let bytes = secbytes.map_read(Bytes::new);
///
/// assert_eq!(bytes, [1; 8][..]);
/// ```
#[derive(Clone, Debug)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    /// Create a new Bytes.
    pub fn new(input: &[u8]) -> Bytes {
        Bytes(input.into())
    }

    /// Create a randomly Bytes.
    pub fn random(len: usize) -> Bytes {
        let mut output = vec![0; len];
        rand!(fill output);
        Bytes(output)
    }
}

impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl PartialEq<[u8]> for Bytes {
    /// Constant time eq.
    fn eq(&self, rhs: &[u8]) -> bool {
        if self.0.len() == rhs.len() {
            unsafe {
                memcmp(self.0.as_ptr(), rhs.as_ptr(), self.0.len()) == 0
            }
        } else {
            false
        }
    }
}

impl PartialEq<Bytes> for Bytes {
    /// Constant time eq.
    fn eq(&self, rhs: &Bytes) -> bool {
        self.eq(rhs.deref())
    }
}

impl Eq for Bytes {}

impl Drop for Bytes {
    /// When drop, it will call `memzero`.
    fn drop(&mut self) {
        unsafe { memzero(self.0.as_mut_ptr(), self.0.len()) };
    }
}
