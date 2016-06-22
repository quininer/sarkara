use ::utils::Bytes;
use super::StreamCipher;


pub struct HC256 {
    pub key: Bytes
}

impl StreamCipher for HC256 {
    fn new(key: &[u8]) -> Self {
        HC256 { key: Bytes::new(key) }
    }

    fn process(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let mut output = vec![0; data.len()];
        ::hc256::HC256::new(&self.key, nonce)
            .process(data, &mut output);
        output
    }
}
