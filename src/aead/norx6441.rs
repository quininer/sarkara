use std::cmp;
use arrayref::{ array_ref, array_mut_ref };
use norx::constant::{ KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, BLOCK_LENGTH };
use norx::{ Norx as NorxCipher, Process, Encrypt, Decrypt };
use crate::Error;
use super::{ AeadCipher, Online, Encryption, Decryption };


pub struct Norx6441([u8; KEY_LENGTH]);

pub struct EncryptProcess<'a> {
    process: Process<Encrypt>,
    key: &'a [u8; KEY_LENGTH]
}

pub struct DecryptProcess<'a> {
    process: Process<Decrypt>,
    key: &'a [u8; KEY_LENGTH]
}

impl AeadCipher for Norx6441 {
    const KEY_LENGTH: usize = KEY_LENGTH;
    const NONCE_LENGTH: usize = NONCE_LENGTH;
    const TAG_LENGTH: usize = TAG_LENGTH;

    fn new(key: &[u8]) -> Self {
        let mut k = [0; KEY_LENGTH];
        k.copy_from_slice(key);
        Norx6441(k)
    }

    fn seal(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        self.encrypt(nonce, aad).finalize(input, output)
    }

    fn open(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        self.decrypt(nonce, aad).finalize(input, output)
    }
}

impl<'a> Online<'a> for Norx6441 {
    type Encryption = EncryptProcess<'a>;
    type Decryption = DecryptProcess<'a>;

    fn encrypt(&'a self, nonce: &[u8], aad: &[u8]) -> Self::Encryption {
        let nonce = array_ref!(nonce, 0, NONCE_LENGTH);
        EncryptProcess {
            process: NorxCipher::new(&self.0, nonce).encrypt(aad),
            key: &self.0
        }
    }

    fn decrypt(&'a self, nonce: &[u8], aad: &[u8]) -> Self::Decryption {
        let nonce = array_ref!(nonce, 0, NONCE_LENGTH);
        DecryptProcess {
            process: NorxCipher::new(&self.0, nonce).decrypt(aad),
            key: &self.0
        }
    }
}

impl<'a> Encryption<'a> for EncryptProcess<'a> {
    fn process<'b>(&mut self, input: &[u8], output: &'b mut [u8]) -> &'b [u8] {
        let len = cmp::min(input.len(), output.len());

        let (input, _) = input.split_at(len - len % BLOCK_LENGTH);
        let (output, _) = output.split_at_mut(input.len());

        self.process.process(
            input.chunks(BLOCK_LENGTH)
                .zip(output.chunks_mut(BLOCK_LENGTH))
                .map(|(input, output)| (
                    array_ref!(input, 0, BLOCK_LENGTH),
                    array_mut_ref!(output, 0, BLOCK_LENGTH)
                ))
        );

        output
    }

    fn finalize(mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        if input.len() + TAG_LENGTH != output.len() {
            return Err(Error::Length);
        }

        let take = self.process(input, output).len();
        let (_, input) = input.split_at(take);
        let (_, output) = output.split_at_mut(take);
        self.process.finalize(self.key, &[], input, output);

        Ok(())
    }
}

impl<'a> Decryption<'a> for DecryptProcess<'a> {
    fn process<'b>(&mut self, input: &[u8], output: &'b mut [u8]) -> &'b [u8] {
        let len = cmp::min(input.len(), output.len());

        let (input, _) = input.split_at(len - len % BLOCK_LENGTH);
        let (output, _) = output.split_at_mut(input.len());

        self.process.process(
            input.chunks(BLOCK_LENGTH)
                .zip(output.chunks_mut(BLOCK_LENGTH))
                .map(|(input, output)| (
                    array_ref!(input, 0, BLOCK_LENGTH),
                    array_mut_ref!(output, 0, BLOCK_LENGTH)
                ))
        );

        output
    }

    fn finalize(mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        if input.len() != output.len() + TAG_LENGTH {
            return Err(Error::Length);
        }

        let take = self.process(input, output).len();
        let (_, input) = input.split_at(take);
        let (_, output) = output.split_at_mut(take);

        if self.process.finalize(self.key, &[], input, output) {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}
