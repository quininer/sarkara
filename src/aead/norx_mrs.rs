use norx_permutation::{ U, S, norx };
use mem_aead_mrs::{
    KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH,
    Mrs, Permutation
};
use crate::Error;
use super::AeadCipher;


pub struct NorxMRS([u8; KEY_LENGTH]);

impl AeadCipher for NorxMRS {
    const KEY_LENGTH: usize = KEY_LENGTH;
    const NONCE_LENGTH: usize = NONCE_LENGTH;
    const TAG_LENGTH: usize = TAG_LENGTH;

    fn new(key: &[u8]) -> Self {
        let mut k = [0; KEY_LENGTH];
        k.copy_from_slice(key);
        NorxMRS(k)
    }

    fn seal(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        if nonce.len() != Self::NONCE_LENGTH ||
            input.len() + Self::TAG_LENGTH != output.len()
        {
            return Err(Error::Length);
        }

        let (output, tag) = output.split_at_mut(input.len());
        output.copy_from_slice(input);
        let NorxMRS(key) = self;
        let tag = array_mut_ref!(tag, 0, TAG_LENGTH);
        let nonce = array_ref!(nonce, 0, NONCE_LENGTH);

        Mrs::<Norx644P>::new()
            .encrypt(key, nonce, aad, output, tag);

        Ok(())
    }

    fn open(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        if nonce.len() != Self::NONCE_LENGTH ||
            input.len() != output.len() + Self::TAG_LENGTH
        {
            return Err(Error::Length);
        }

        let (input, tag) = input.split_at(output.len());
        output.copy_from_slice(input);
        let NorxMRS(key) = self;
        let tag = array_ref!(tag, 0, TAG_LENGTH);
        let nonce = array_ref!(nonce, 0, NONCE_LENGTH);

        if Mrs::<Norx644P>::new()
            .decrypt(key, nonce, aad, output, tag)
        {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}


enum Norx644P {}

impl Permutation for Norx644P {
    #[inline]
    fn permutation(state: &mut [U; S]) {
        norx(state)
    }
}
