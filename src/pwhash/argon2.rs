use argon2rs::{ Argon2, Variant, ParamErr };
use ::utils::Bytes;
use super::{ KeyDerive, KeyVerify, Key };


pub const OPSLIMIT_INTERACTIVE: u32 = 4;
pub const MEMLIMIT_INTERACTIVE: u32 = 33554432;
pub const OPSLIMIT_MODERATE: u32 = 6;
pub const MEMLIMIT_MODERATE: u32 = 134217728;
pub const OPSLIMIT_SENSITIVE: u32 = 8;
pub const MEMLIMIT_SENSITIVE: u32 = 536870912;

pub struct Argon2i {
    pub key: Bytes,
    pub aad: Bytes,
    pub passes: u32,
    pub lanes: u32,
    pub kib: u32
}

impl Default for Argon2i {
    fn default() -> Argon2i {
        Argon2i {
            key: Bytes(Vec::new()),
            aad: Bytes(Vec::new()),
            passes: OPSLIMIT_INTERACTIVE,
            lanes: 1,
            kib: MEMLIMIT_INTERACTIVE / 1024
        }
    }
}

impl KeyDerive for Argon2i {
    fn with_key(mut self, key: &[u8]) -> Self {
        self.key = Bytes::new(key);
        self
    }
    fn with_aad(mut self, aad: &[u8]) -> Self {
        self.aad = Bytes::new(aad);
        self
    }
    fn with_opslimit(mut self, opslimit: u32) -> Self {
        self.passes = opslimit;
        self
    }
    fn with_memlimit(mut self, memlimit: u32) -> Self {
        self.kib = memlimit / 1024;
        self
    }

    fn derive(&self, password: &[u8], salt: &[u8], outlen: usize) -> Result<Key, ParamErr> {
        let mut output = Bytes(vec![0; outlen]);
        Argon2::new(self.passes, self.lanes, self.kib, Variant::Argon2i)?
            .hash(&mut output, password, salt, &self.key, &self.aad);
        Ok(output)
    }
}

impl KeyVerify for Argon2i {
    fn verify(&self, password: &[u8], salt: &[u8], hash: &[u8]) -> Result<bool, ParamErr> {
        Ok(self.derive(password, salt, hash.len())? == hash[..])
    }
}
