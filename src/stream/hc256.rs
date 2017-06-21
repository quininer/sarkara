//! [hc256](http://www.ecrypt.eu.org/stream/hcpf.html).

use seckey::Bytes;
use super::StreamCipher;


/// HC256.
///
/// # Example(process)
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// use rand::{ Rng, thread_rng };
/// use sarkara::stream::{ HC256, StreamCipher };
///
/// // ...
/// # let mut rng = thread_rng();
/// # let mut pass = vec![0; HC256::KEY_LENGTH];
/// # let mut nonce = vec![0; HC256::NONCE_LENGTH];
/// # let mut data = vec![0; 1024];
/// # rng.fill_bytes(&mut pass);
/// # rng.fill_bytes(&mut nonce);
/// # rng.fill_bytes(&mut data);
///
/// let cipher = HC256::new(&pass);
/// let ciphertext = cipher.process(&nonce, &data);
/// let plaintext = cipher.process(&nonce, &ciphertext);
/// assert_eq!(plaintext, data);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct HC256 {
    key: Bytes
}

impl StreamCipher for HC256 {
    fn new(key: &[u8]) -> Self where Self: Sized {
        assert_eq!(key.len(), Self::KEY_LENGTH);
        HC256 { key: Bytes::new(key) }
    }

    const KEY_LENGTH: usize = 32;
    const NONCE_LENGTH: usize = 32;

    fn process(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        assert_eq!(nonce.len(), Self::NONCE_LENGTH);
        let mut output = vec![0; data.len()];
        ::hc256::HC256::new(&self.key, nonce)
            .process(data, &mut output);
        output
    }
}
