use std::num::Wrapping;
use rand::Rng;
use byteorder::{ LittleEndian, ByteOrder };


/// Nonce Generater trait.
pub trait Nonce {
    /// fill nonce.
    fn fill(&mut self, nonce: &mut [u8]);
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
/// # type HHB = General<HC256, HMAC<Blake2b>, Blake2b>;
/// #
/// # let mut rng = OsRng::new().unwrap();
/// # let mut key = vec![0; HHB::key_length()];
/// # let mut plaintext = vec![0; 1024];
/// # rng.fill_bytes(&mut key);
/// # rng.fill_bytes(&mut plaintext);
/// #
/// let mut nonce = RngCounter::new(OsRng::new().unwrap().gen::<ChaChaRng>());
///
/// let ciphertext = HHB::seal_with_nonce(&mut nonce, &key, &plaintext);
/// # assert_eq!(HHB::open(&key, &ciphertext).unwrap(), &plaintext[..]);
/// #
/// # let ciphertext = HHB::seal_with_nonce(&mut nonce, &key, &plaintext);
/// # assert_eq!(HHB::open(&key, &ciphertext).unwrap(), &plaintext[..]);
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
        RngCounter {
            rng: rng,
            ctr: Wrapping(0)
        }
    }
}

impl<R> Nonce for RngCounter<R> where R: Rng {
    fn fill(&mut self, nonce: &mut [u8]) {
        const ONE: Wrapping<u64> = Wrapping(1);

        let len = nonce.len();
        debug_assert!(len >= 8);
        let (mut r, mut l) = nonce.split_at_mut(len - 8);
        self.rng.fill_bytes(&mut r);
        LittleEndian::write_u64(&mut l, self.ctr.0);
        self.ctr |= ONE;
    }
}

impl<T> Nonce for T where T: Rng {
    #[inline]
    fn fill(&mut self, nonce: &mut [u8]) {
        self.fill_bytes(nonce)
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
