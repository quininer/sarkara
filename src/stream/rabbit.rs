use super::StreamCipher;


/// Rabbit.
///
/// # Example(process)
/// ```
/// use sarkara::utils::Bytes;
/// use sarkara::stream::{ Rabbit, StreamCipher };
///
/// let (pass, nonce) = (Bytes::random(16), Bytes::random(8));
/// let data = [8; 64];
/// let mut cipher = Rabbit::new(&pass);
/// let ciphertext = cipher.process(&nonce, &data);
/// let plaintext = cipher.process(&nonce, &ciphertext);
/// assert_eq!(plaintext, &data[..]);
/// ```
pub struct Rabbit {
    inner: ::rabbit::Rabbit
}

impl StreamCipher for Rabbit {
    fn new(key: &[u8]) -> Self {
        Rabbit { inner: ::rabbit::Rabbit::new(&key.into()) }
    }

    #[inline] fn key_length() -> usize { 16 }
    #[inline] fn nonce_length() -> usize { 8 }

    fn process(&mut self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let mut output = vec![0; data.len()];
        self.inner.reinit(&nonce.into());
        self.inner.encrypt(data, &mut output);
        output
    }
}
