mod hc256;

pub use self::hc256::HC256;


pub trait StreamCipher {
    fn new(key: &[u8]) -> Self;
    fn process(&self, nonce: &[u8], data: &[u8]) -> Vec<u8>;
}
