use std::num::Wrapping;
use rand::Rng;
use byteorder::{ LittleEndian, ByteOrder };


const ONE: Wrapping<u64> = Wrapping(1);

/// Nonce Generater trait.
pub trait GenNonce {
    /// fill nonce.
    fn fill(&mut self, nonce: &mut [u8]);
}

impl<T> GenNonce for T where T: Rng {
    #[inline]
    fn fill(&mut self, nonce: &mut [u8]) {
        self.fill_bytes(nonce)
    }
}

/// Rng + Counter Nonce Generater.
///
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// # use rand::{ OsRng, ChaChaRng, Rng };
/// # use sarkara::secretbox::SecretBox;
/// # use sarkara::aead::{ General, AeadCipher };
/// # use sarkara::stream::HC256;
/// # use sarkara::auth::HMAC;
/// # use sarkara::hash::Blake2b;
/// # use sarkara::utils::RngCounter;
/// #
/// # type HHBB = General<HC256, HMAC<Blake2b>, Blake2b>;
/// #
/// # let mut rng = OsRng::new().unwrap();
/// # let mut key = vec![0; HHBB::key_length()];
/// # let mut plaintext = vec![0; 1024];
/// # rng.fill_bytes(&mut key);
/// # rng.fill_bytes(&mut plaintext);
/// #
/// let mut nonce = RngCounter::new(OsRng::new().unwrap().gen::<ChaChaRng>());
///
/// let ciphertext = HHBB::seal_with_nonce(&mut nonce, &key, &plaintext);
/// # assert_eq!(HHBB::open(&key, &ciphertext).unwrap(), &plaintext[..]);
/// #
/// # let ciphertext = HHBB::seal_with_nonce(&mut nonce, &key, &plaintext);
/// # assert_eq!(HHBB::open(&key, &ciphertext).unwrap(), &plaintext[..]);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct RngCounter<R> {
    rng: R,
    ctr: Wrapping<u64>
}

impl<R> RngCounter<R> where R: Rng {
    /// Create a new RngCounter.
    pub fn new(rng: R) -> RngCounter<R> {
        RngCounter { rng: rng, ctr: Wrapping(0) }
    }
}

impl<R> GenNonce for RngCounter<R> where R: Rng {
    fn fill(&mut self, nonce: &mut [u8]) {
        let len = nonce.len();
        debug_assert!(len >= 8);
        let (r, l) = nonce.split_at_mut(len - 8);
        self.rng.fill_bytes(r);
        LittleEndian::write_u64(l, self.ctr.0);
        self.ctr |= ONE;
    }
}

/// Fixed Nonce + Counter Nonce Generater.
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
/// # use sarkara::utils::{ NonceCounter, GenNonce };
/// #
/// # type HHBB = General<HC256, HMAC<Blake2b>, Blake2b>;
/// #
/// # let mut rng = OsRng::new().unwrap();
/// # let mut key = vec![0; HHBB::key_length()];
/// # let mut fixed_nonce = vec![0; HHBB::nonce_length()];
/// # let mut plaintext = vec![0; 1024];
/// # rng.fill_bytes(&mut key);
/// # rng.fill_bytes(&mut plaintext);
/// # rng.fill_bytes(&mut fixed_nonce);
/// #
/// let mut nonce1 = NonceCounter::new(&fixed_nonce);
/// let mut nonce2 = NonceCounter::new(&fixed_nonce);
///
/// let mut tmp_nonce = vec![0; HHBB::nonce_length()];
/// nonce1.fill(&mut tmp_nonce);
/// let ciphertext = HHBB::new(&key)
///     .with_aad(&tmp_nonce)
///     .encrypt(&mut tmp_nonce, &plaintext);
///
/// let mut tmp_nonce = vec![0; HHBB::nonce_length()];
/// nonce2.fill(&mut tmp_nonce);
/// let decrypttext = HHBB::new(&key)
///     .with_aad(&tmp_nonce)
///     .decrypt(&tmp_nonce, &ciphertext).unwrap();
/// # assert_eq!(decrypttext, plaintext);
/// # }
/// ```
pub struct NonceCounter {
    fixed: Vec<u8>,
    ctr: Wrapping<u64>
}

impl NonceCounter {
    /// Create a new NonceCounter.
    pub fn new(nonce: &[u8]) -> NonceCounter {
        NonceCounter { fixed: nonce.into(), ctr: Wrapping(0) }
    }
}

impl GenNonce for NonceCounter {
    fn fill(&mut self, nonce: &mut [u8]) {
        let len = nonce.len();
        debug_assert!(len >= 8 && len <= self.fixed.len());
        nonce.clone_from_slice(&self.fixed[..len]);
        let mut ctr = [0; 8];
        LittleEndian::write_u64(&mut ctr, self.ctr.0);
        self.ctr |= ONE;
        for (n, &c) in nonce.iter_mut().skip(len - 8).zip(&ctr) {
            *n ^= c;
        }
    }
}


#[test]
fn test_rngcounter() {
    use rand::{ OsRng, ChaChaRng };

    let mut output = [0; 12];
    let mut rngctr = RngCounter::new(OsRng::new().unwrap().gen::<ChaChaRng>());

    rngctr.fill(&mut output);
    assert_eq!(LittleEndian::read_u64(&output[4..]), 0);

    rngctr.fill(&mut output);
    assert_eq!(LittleEndian::read_u64(&output[4..]), 1);
}

#[test]
fn test_noncecounter() {
    let fixed_nonce = [99; 12];
    let mut output = [0; 12];
    let mut noncectr = NonceCounter::new(&fixed_nonce);

    noncectr.fill(&mut output);
    for i in 0..12 {
        output[i] ^= fixed_nonce[i];
    }
    assert_eq!(LittleEndian::read_u64(&output[4..]), 0);

    noncectr.fill(&mut output);
    for i in 0..12 {
        output[i] ^= fixed_nonce[i];
    }
    assert_eq!(LittleEndian::read_u64(&output[4..]), 1);
}
