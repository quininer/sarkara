use ::utils::Bytes;
use super::StreamCipher;


/// HC128.
///
/// # Example(process)
/// ```
/// use sarkara::utils::Bytes;
/// use sarkara::stream::{ HC128, StreamCipher };
///
/// let (pass, nonce) = (
///     Bytes::random(HC128::key_length()),
///     Bytes::random(HC128::nonce_length())
/// );
/// let data = [8; 64];
/// let mut cipher = HC128::new(&pass);
/// let ciphertext = cipher.process(&nonce, &data);
/// let plaintext = cipher.process(&nonce, &ciphertext);
/// assert_eq!(plaintext, &data[..]);
/// ```
pub struct HC128 {
    key: Bytes
}

impl StreamCipher for HC128 {
    fn new(key: &[u8]) -> Self {
        HC128 { key: Bytes::new(key) }
    }

    #[inline] fn key_length() -> usize { 16 }
    #[inline] fn nonce_length() -> usize { 16 }

    fn process(&mut self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let mut output = vec![0; data.len()];
        ::hc128::HC128::new(&self.key, nonce)
            .process(data, &mut output);
        output
    }
}
