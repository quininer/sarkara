//! Nonce Generater.

use std::mem::size_of_val;
use rand::Rng;
use byteorder::{ BigEndian, ByteOrder };


/// Nonce Generater trait.
pub trait GenNonce {
    /// fill nonce.
    fn fill(&mut self, nonce: &mut [u8]);

    /// generate nonce.
    fn gen(&mut self, len: usize) -> Vec<u8> {
        let mut output = vec![0; len];
        self.fill(&mut output);
        output
    }
}

impl<T: Rng> GenNonce for T {
    #[inline]
    fn fill(&mut self, nonce: &mut [u8]) {
        self.fill_bytes(nonce)
    }
}


/// u64 Counter Nonce Generater.
///
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// # use rand::{ OsRng, ChaChaRng, Rng };
/// # use sarkara::aead::{ General, AeadCipher };
/// # use sarkara::stream::HC256;
/// # use sarkara::auth::HMAC;
/// # use sarkara::hash::Blake2b;
/// # use sarkara::utils::nonce::{ GenNonce, Counter };
/// #
/// # type HHBB = General<HC256, HMAC<Blake2b>, Blake2b>;
/// #
/// # let mut rng = OsRng::new().unwrap();
/// # let mut key = vec![0; HHBB::key_length()];
/// # let mut plaintext = vec![0; 1024];
/// # rng.fill_bytes(&mut key);
/// # rng.fill_bytes(&mut plaintext);
/// #
/// let mut ctr1 = Counter::default();
/// let mut ctr2 = Counter::default();
///
/// let mut nonce = vec![0; HHBB::nonce_length()];
/// ctr1.fill(&mut nonce);
/// let ciphertext = HHBB::new(&key)
///     .with_aad(&nonce)
///     .encrypt(&mut nonce, &plaintext);
///
/// let mut nonce = vec![0; HHBB::nonce_length()];
/// ctr2.fill(&mut nonce);
/// let decrypttext = HHBB::new(&key)
///     .with_aad(&nonce)
///     .decrypt(&nonce, &ciphertext).unwrap();
/// # assert_eq!(decrypttext, plaintext);
/// # }
/// ```
///
/// ## Panic When:
/// - Counter overflow.
/// - nonce length < `size_of::<u64>()`.
#[derive(Debug, Clone)]
pub struct Counter(pub u64);

impl Default for Counter {
    fn default() -> Counter {
        Counter(0)
    }
}

impl GenNonce for Counter {
    fn fill(&mut self, nonce: &mut [u8]) {
        let nonce_len = nonce.len();
        let ctr_len = size_of_val(&self.0);
        assert!(nonce_len >= ctr_len);

        let (_, ctr) = nonce.split_at_mut(nonce_len - ctr_len);
        BigEndian::write_u64(ctr, self.0);
        self.0 = self.0.checked_add(1).expect("Counter overflow.");
    }
}


#[test]
fn test_counter() {
    let mut output = [0; 12];
    let mut ctr = Counter::default();

    ctr.fill(&mut output);
    assert_eq!(BigEndian::read_u64(&output[4..]), 0);

    ctr.fill(&mut output);
    assert_eq!(BigEndian::read_u64(&output[4..]), 1);
}
