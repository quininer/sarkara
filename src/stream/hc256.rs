use ::utils::Bytes;
use super::StreamCipher;


/// HC256.
///
/// # Example(process)
/// ```
/// use sarkara::utils::Bytes;
/// use sarkara::stream::{ HC256, StreamCipher };
///
/// let (pass, nonce) = (
///     Bytes::random(HC256::key_length()),
///     Bytes::random(HC256::nonce_length())
/// );
/// let data = [8; 64];
/// let mut cipher = HC256::new(&pass);
/// let ciphertext = cipher.process(&nonce, &data);
/// let plaintext = cipher.process(&nonce, &ciphertext);
/// assert_eq!(plaintext, &data[..]);
/// ```
pub struct HC256 {
    key: Bytes
}

impl StreamCipher for HC256 {
    fn new(key: &[u8]) -> Self {
        HC256 { key: Bytes::new(key) }
    }

    #[inline] fn key_length() -> usize { 32 }
    #[inline] fn nonce_length() -> usize { 32 }

    fn process(&mut self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let mut output = vec![0; data.len()];
        ::hc256::HC256::new(&self.key, nonce)
            .process(data, &mut output);
        output
    }
}
