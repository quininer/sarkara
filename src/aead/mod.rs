use ::Error;

pub mod norx6441;


pub trait AeadCipher {
    const KEY_LENGTH: usize;
    const NONCE_LENGTH: usize;
    const TAG_LENGTH: usize;

    /// TODO should be `Self::KEY_LENGTH`
    fn new(key: &[u8]) -> Self;
    /// TODO should be `Self::NONCE_LENGTH`
    fn seal(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Error>;
    fn open(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Error>;
}


// TODO GAT https://github.com/rust-lang/rust/issues/44265
pub trait Online<'a>: AeadCipher {
    type Encryption: Encryption<'a>;
    type Decryption: Decryption<'a>;

    /// TODO should be `Self::NONCE_LENGTH`
    fn encrypt(&'a self, nonce: &[u8], aad: &[u8]) -> Self::Encryption;
    /// TODO should be `Self::NONCE_LENGTH`
    fn decrypt(&'a self, nonce: &[u8], aad: &[u8]) -> Self::Decryption;
}

pub trait Encryption<'a> {
    fn process<'b>(&mut self, input: &[u8], output: &'b mut [u8]) -> &'b [u8];
    fn finalize(self, input: &[u8], output: &mut [u8]) -> Result<(), Error>;
}

pub trait Decryption<'a> {
    fn process<'b>(&mut self, input: &[u8], output: &'b mut [u8]) -> &'b [u8];
    fn finalize(self, input: &[u8], output: &mut [u8]) -> Result<(), Error>;
}
