use ::hash::GenericHash;
use ::utils::Bytes;
use super::{ Mac, NonceMac, Tag };


/// HMAC nonce variant.
///
/// `H(nonce, K xor opad || H(nonce, K xor ipad || text))`
pub struct HMAC {
    pub nonce: Bytes
}

impl Default for HMAC {
    fn default() -> Self {
        HMAC { nonce: Bytes(Vec::new()) }
    }
}

impl<H: GenericHash> Mac<H> for HMAC {
    fn result(&self, key: &[u8], data: &[u8]) -> Tag {
        let mut ipad = vec![0x36; 64];
        let mut opad = vec![0x5c; 64];

        for i in 0..key.len() {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }

        ipad.extend_from_slice(data);
        opad.extend_from_slice(
            &H::new()
                .with_key(&self.nonce)
                .hash(&ipad)
        );

        H::new()
            .with_key(&self.nonce)
            .hash(&opad)
    }
}

impl<H: GenericHash> NonceMac<H> for HMAC {
    fn with_nonce(mut self, nonce: &[u8]) -> Self {
        self.nonce = Bytes::new(nonce);
        self
    }
}
