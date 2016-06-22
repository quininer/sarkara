use ::hash::{ Hash, GenericHash };
use super::{ Mac, NonceMac, Tag };


/// HMAC nonce variant.
///
/// `H(nonce, K xor opad || H(nonce, K xor ipad || text))`
#[derive(Clone, Debug)]
pub struct HMAC<H> {
    ih: H,
    oh: H
}

impl<H: Hash> Default for HMAC<H> {
    fn default() -> Self {
        HMAC {
            ih: H::new(),
            oh: H::new()
        }
    }
}

impl<H: Hash> Mac for HMAC<H> {
    fn result(&self, key: &[u8], data: &[u8]) -> Tag {
        let mut ipad = vec![0x36; 64];
        let mut opad = vec![0x5c; 64];

        for i in 0..key.len() {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }

        ipad.extend_from_slice(data);
        opad.extend_from_slice(&self.ih.hash(&ipad));

        self.oh.hash(&opad)
    }
}

impl<H: GenericHash> NonceMac for HMAC<H> {
    fn with_nonce(&mut self, nonce: &[u8]) -> &mut Self {
        self.ih.with_key(nonce);
        self.oh.with_key(nonce);
        self
    }
}
