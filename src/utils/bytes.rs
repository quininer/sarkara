use std::fmt;
use std::iter::repeat;
use std::ops::{ Deref, DerefMut };
use memsec::{ memcmp, mlock, munlock };


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
#[derive(Clone)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    /// Create a new Bytes.
    pub fn new(input: &[u8]) -> Bytes {
        let mut input: Vec<u8> = input.into();
        unsafe { mlock(input.as_mut_ptr(), input.len()) };
        Bytes(input)
    }

    /// Create a randomly Bytes.
    pub fn random(len: usize) -> Bytes {
        let mut input = vec![0; len];
        rand!(fill input);
        unsafe { mlock(input.as_mut_ptr(), input.len()) };
        Bytes(input)
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(mut t: Vec<u8>) -> Bytes {
        unsafe { mlock(t.as_mut_ptr(), t.len()) };
        Bytes(t)
    }
}

impl<'a> From<&'a [u8]> for Bytes {
    fn from(t: &'a [u8]) -> Bytes {
        Bytes::new(t)
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

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", repeat('*').take(self.0.len()).collect::<String>())
    }
}

impl PartialEq<[u8]> for Bytes {
    /// Constant time eq.
    fn eq(&self, rhs: &[u8]) -> bool {
        if self.0.len() == rhs.len() {
            unsafe { memcmp(
                self.0.as_ptr(),
                rhs.as_ptr(),
                self.0.len()
            ) == 0 }
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
    /// When drop, it will call `munlock`.
    fn drop(&mut self) {
        unsafe { munlock(self.0.as_mut_ptr(), self.0.len()) };
    }
}
