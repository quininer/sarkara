use std::cmp;
use sparx_cipher::Sparx;
use sparx_cipher::params::{ KEY_BYTES, BLOCK_BYTES };
use colm::{ NONCE_LENGTH, Colm, E, D, Process0 };
use colm::traits::BlockCipher;
use super::{ AeadCipher, Online, Encryption, Decryption };



pub type Sparx256Colm0 = Colm<Sparx256>;
pub type EncryptProcess<'a> = Process0<'a, Sparx256, E>;
pub type DecryptProcess<'a> = Process0<'a, Sparx256, D>;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "input/output length does not match")]
    Length
}

impl AeadCipher for Sparx256Colm0 {
    const KEY_LENGTH: usize = Sparx256::KEY_LENGTH;
    const NONCE_LENGTH: usize = NONCE_LENGTH;
    const TAG_LENGTH: usize = BLOCK_BYTES;

    type Error = Error;

    /// TODO should be `Self::KEY_LENGTH`
    fn new(key: &[u8]) -> Self {
        let key = array_ref!(key, 0, KEY_BYTES);
        Sparx256Colm0::new(key)
    }

    fn seal(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Self::Error> {
        let process = <Self as Online>::encrypt(self, nonce, aad);

        <<Self as Online>::Encryption as Encryption<_>>::finalize(process, input, output)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<bool, Self::Error> {
        let process = <Self as Online>::decrypt(self, nonce, aad);

        <<Self as Online>::Decryption as Decryption<_>>::finalize(process, input, output)
    }
}

impl<'a> Online<'a> for Sparx256Colm0 {
    type Encryption = EncryptProcess<'a>;
    type Decryption = DecryptProcess<'a>;

    /// TODO should be `Self::NONCE_LENGTH`
    fn encrypt(&'a self, nonce: &[u8], aad: &[u8]) -> Self::Encryption {
        let nonce = array_ref!(nonce, 0, NONCE_LENGTH);
        Sparx256Colm0::encrypt(self, nonce, aad)
    }

    /// TODO should be `Self::NONCE_LENGTH`
    fn decrypt(&'a self, nonce: &[u8], aad: &[u8]) -> Self::Decryption {
        let nonce = array_ref!(nonce, 0, NONCE_LENGTH);
        Sparx256Colm0::decrypt(self, nonce, aad)
    }
}


impl<'a> Encryption<'a, Error> for EncryptProcess<'a> {
    fn process<'b>(&mut self, input: &'b [u8], output: &mut [u8]) -> Result<(), &'b [u8]> {
        let len = cmp::min(input.len(), output.len());

        let take =
            if len == 0 { 0 }
            else if len % BLOCK_BYTES == 0 { (len / BLOCK_BYTES - 1) * BLOCK_BYTES }
            else { len / BLOCK_BYTES * BLOCK_BYTES };

        let (input, remaining) = input.split_at(take);
        let (output, _) = output.split_at_mut(take);

        for (input, output) in input.chunks(BLOCK_BYTES)
            .zip(output.chunks_mut(BLOCK_BYTES))
        {
            let input = array_ref!(input, 0, BLOCK_BYTES);
            let output = array_mut_ref!(output, 0, BLOCK_BYTES);

            Self::process(self, input, output);
        }

        Err(remaining)
    }

    fn finalize(mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        if input.is_empty() || input.len() + BLOCK_BYTES != output.len() {
            return Err(Error::Length);
        }

        if let Err(buf) = <Self as Encryption<_>>::process(&mut self, input, output) {
            let (_, output) = output.split_at_mut(input.len() - buf.len());
            Self::finalize(self, buf, output);
        } else {
            unreachable!()
        }

        Ok(())
    }
}

impl<'a> Decryption<'a, Error> for DecryptProcess<'a> {
    fn process<'b>(&mut self, input: &'b [u8], output: &mut [u8]) -> Result<(), &'b [u8]> {
        let len = cmp::min(input.len(), output.len());

        let take =
            if len == 0 { 0 }
            else if len % BLOCK_BYTES == 0 { (len / BLOCK_BYTES - 2) * BLOCK_BYTES }
            else { (len / BLOCK_BYTES - 1) * BLOCK_BYTES };

        let (input, remaining) = input.split_at(take);
        let (output, _) = output.split_at_mut(take);

        for (input, output) in input.chunks(BLOCK_BYTES)
            .zip(output.chunks_mut(BLOCK_BYTES))
        {
            let input = array_ref!(input, 0, BLOCK_BYTES);
            let output = array_mut_ref!(output, 0, BLOCK_BYTES);

            Self::process(self, input, output);
        }

        Err(remaining)
    }

    fn finalize(mut self, input: &[u8], output: &mut [u8]) -> Result<bool, Error> {
        if
            input.is_empty() ||
            input.len() <= BLOCK_BYTES ||
            input.len() != output.len() + BLOCK_BYTES
        {
            return Err(Error::Length);
        }

        if let Err(buf) = <Self as Decryption<_>>::process(&mut self, input, output) {
            let (_, output) = output.split_at_mut(input.len() - buf.len());
            Ok(Self::finalize(self, buf, output))
        } else {
            unreachable!()
        }
    }
}



pub struct Sparx256(pub Sparx);

impl BlockCipher for Sparx256 {
    const KEY_LENGTH: usize = KEY_BYTES;
    const BLOCK_LENGTH: usize = BLOCK_BYTES;

    #[inline]
    fn new(key: &[u8; KEY_BYTES]) -> Self {
        Sparx256(Sparx::new(key))
    }

    #[inline]
    fn encrypt(&self, block: &mut [u8; BLOCK_BYTES]) {
        self.0.encrypt(block)
    }

    #[inline]
    fn decrypt(&self, block: &mut [u8; BLOCK_BYTES]) {
        self.0.decrypt(block)
    }
}
