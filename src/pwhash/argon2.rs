use argon2rs::{ Argon2, Variant, ParamErr };
use ::utils::Bytes;
use super::{ KeyDerive, Key };


pub const OPSLIMIT_INTERACTIVE: u32 = 4;
pub const MEMLIMIT_INTERACTIVE: u32 = 33554432;
pub const OPSLIMIT_MODERATE: u32 = 6;
pub const MEMLIMIT_MODERATE: u32 = 134217728;
pub const OPSLIMIT_SENSITIVE: u32 = 8;
pub const MEMLIMIT_SENSITIVE: u32 = 536870912;

#[derive(Clone, Debug)]
pub struct Argon2i {
    pub key: Bytes,
    pub aad: Bytes,
    pub outlen: usize,
    pub passes: u32,
    pub lanes: u32,
    pub kib: u32
}

impl Default for Argon2i {
    fn default() -> Argon2i {
        Argon2i {
            key: Bytes(Vec::new()),
            aad: Bytes(Vec::new()),
            outlen: 16,
            passes: OPSLIMIT_INTERACTIVE,
            lanes: 1,
            kib: MEMLIMIT_INTERACTIVE / 1024
        }
    }
}

impl KeyDerive for Argon2i {
    fn with_size(&mut self, len: usize) -> &mut Self {
        self.outlen = len;
        self
    }
    fn with_key(&mut self, key: &[u8]) -> &mut Self {
        self.key = Bytes::new(key);
        self
    }
    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = Bytes::new(aad);
        self
    }
    fn with_opslimit(&mut self, opslimit: u32) -> &mut Self {
        self.passes = opslimit;
        self
    }
    fn with_memlimit(&mut self, memlimit: u32) -> &mut Self {
        self.kib = memlimit / 1024;
        self
    }

    fn derive(&self, password: &[u8], salt: &[u8]) -> Result<Key, ParamErr> {
        let mut output = Bytes(vec![0; self.outlen]);
        Argon2::new(self.passes, self.lanes, self.kib, Variant::Argon2i)?
            .hash(&mut output, password, salt, &self.key, &self.aad);
        Ok(output)
    }
}
