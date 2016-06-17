use std::{ fmt, slice };
use std::iter::repeat;
use std::sync::Mutex;
use std::ptr::copy;
use memsec::{
    allocarray, free,
    unprotected_mprotect, Prot,
};


/// Secure Bytes Box.
/// When you need the password stored in the memory, you should use it.
pub struct SecBytes {
    ptr: *mut u8,
    len: usize,
    lock: Mutex<()>,
}

unsafe impl Send for SecBytes {}
unsafe impl Sync for SecBytes {}

impl SecBytes {
    pub fn new(input: &[u8]) -> Option<SecBytes> {
        let sec_bytes = SecBytes {
            ptr: match unsafe { allocarray(input.len()) } {
                Some(memptr) => memptr,
                None => return None
            },
            len: input.len(),
            lock: Mutex::default(),
        };
        unsafe { copy(input.as_ptr(), sec_bytes.ptr, input.len()) };
        sec_bytes.lock();
        Some(sec_bytes)
    }

    #[inline]
    fn lock(&self) {
        unsafe { unprotected_mprotect(self.ptr, Prot::NoAccess) };
    }

    #[inline]
    fn read(&self) {
        unsafe { unprotected_mprotect(self.ptr, Prot::ReadOnly) };
    }

    #[inline]
    fn release(&self) {
        unsafe { unprotected_mprotect(self.ptr, Prot::ReadWrite) };
    }

    /// Map read. returns closure return value.
    ///
    /// ```
    /// use sarkara::utils::SecBytes;
    ///
    /// let pass = [1; 8];
    /// let secbytes = SecBytes::new(&pass).unwrap(); // should memzero pass.
    /// secbytes.map_read(|bs| assert_eq!(bs, pass));
    /// ```
    ///
    /// Don't call it in `map_read`/`map_write`, this could lead to deadlock.
    ///
    /// ```norun
    /// secbytes.map_read(|_|
    ///     secbytes.map_read(|_| ()) // deadlock!
    /// );
    /// ```
    pub fn map_read<U, F: FnOnce(&[u8]) -> U>(&self, f: F) -> U {
        let lock = match self.lock.lock() {
            Ok(lock) => lock,
            Err(poison) => poison.into_inner()
        };
        self.read();
        let output = f(unsafe { slice::from_raw_parts(self.ptr, self.len) });
        self.lock();
        drop(lock);
        output
    }

    /// Map write. returns closure return value.
    ///
    /// ```
    /// # use sarkara::utils::SecBytes;
    /// #
    /// # let pass = [1; 8];
    /// # let secbytes = SecBytes::new(&pass).unwrap(); // should memzero pass.
    /// secbytes.map_write(|bs| bs[0] = 0);
    /// let bs = secbytes.map_read(|bs| {
    ///     let mut pass = [0; 8];
    ///     pass.clone_from_slice(bs);
    ///     pass
    /// });
    /// assert_eq!(bs, [0, 1, 1, 1, 1, 1, 1, 1])
    /// ```
    pub fn map_write<U, F: FnOnce(&mut [u8]) -> U>(&self, f: F) -> U {
        let lock = match self.lock.lock() {
            Ok(lock) => lock,
            Err(poison) => poison.into_inner()
        };
        self.release();
        let output = f(unsafe { slice::from_raw_parts_mut(self.ptr, self.len) });
        self.lock();
        drop(lock);
        output
    }
}

impl fmt::Debug for SecBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", repeat('*').take(self.len).collect::<String>())
    }
}

impl Drop for SecBytes {
    fn drop(&mut self) {
        unsafe { free(self.ptr) };
    }
}
