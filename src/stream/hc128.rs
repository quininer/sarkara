use ::utils::Bytes;
use super::StreamCipher;


/// HC-128.
///
/// # Example(process)
/// ```
/// use sarkara::utils::Bytes;
/// use sarkara::stream::{ HC128, StreamCipher };
///
/// let (pass, nonce) = (Bytes::random(16), Bytes::random(16));
/// let data = [8; 64];
/// let cipher = HC128::new(&pass);
/// let ciphertext = cipher.process(&nonce, &data);
/// let plaintext = cipher.process(&nonce, &ciphertext);
/// assert_eq!(plaintext, &data[..]);
/// ```
#[derive(Clone, Debug)]
pub struct HC128 {
    /// key.
    pub key: Bytes
}

impl StreamCipher for HC128 {
    fn new(key: &[u8]) -> Self {
        HC128 { key: Bytes::new(key) }
    }

    fn process(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let mut output = vec![0; data.len()];
        ::hc128::HC128::new(&self.key, nonce)
            .process(data, &mut output);
        output
    }
}
