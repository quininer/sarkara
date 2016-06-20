use std::cmp;
use std::ops::{ Deref, DerefMut };
use ::memsec::{ memzero, memcmp };


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
    pub fn new(input: &[u8]) -> Bytes {
        Bytes(input.into())
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

impl cmp::PartialEq<[u8]> for Bytes {
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

impl cmp::PartialEq<Bytes> for Bytes {
    fn eq(&self, rhs: &Bytes) -> bool {
        self.eq(rhs.deref())
    }
}

impl cmp::Eq for Bytes {}

impl Drop for Bytes {
    fn drop(&mut self) {
        unsafe { memzero(self.0.as_mut_ptr(), self.0.len()) };
    }
}
