mod blake2;

use ::utils::Bytes;
pub use self::blake2::{ Blake2b, Blake2s };


pub type Digest = Bytes;

pub trait Hash: Default {
    fn new() -> Self {
        Self::default()
    }
    fn hash(&self, data: &[u8]) -> Digest;
}

pub trait GenericHash: Hash {
    fn with_size(&mut self, nn: usize) -> &mut Self;
    fn with_key(&mut self, key: &[u8]) -> &mut Self;

    fn generichash(nn: usize, key: &[u8], data: &[u8]) -> Digest {
        Self::new()
            .with_size(nn)
            .with_key(key)
            .hash(data)
    }
}
