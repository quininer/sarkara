mod qhmac;

use ::hash::GenericHash;
use ::utils::Bytes;
pub use self::qhmac::HMAC;


pub type Tag = Bytes;

pub trait Mac<H: GenericHash>: Default {
    fn new() -> Self {
        Self::default()
    }

    fn result(&self, key: &[u8], data: &[u8]) -> Tag;
    fn verify(&self, key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        self.result(key, data) == tag[..]
    }
}

pub trait NonceMac<H: GenericHash>: Mac<H> {
    fn with_nonce(mut self, nonce: &[u8]) -> Self;
}
