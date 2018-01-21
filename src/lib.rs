//! Sarkara is a Post-Quantum cryptography library.

#![feature(non_exhaustive)]

#[macro_use] extern crate arrayref;
#[macro_use] extern crate failure;
extern crate rand;
extern crate seckey;
extern crate dilithium;
extern crate kyber;
extern crate sparx_cipher;
extern crate colm;
extern crate norx;

pub mod sign;
pub mod kex;
pub mod aead;
pub mod sealedbox;


pub trait Packing: Sized {
    const BYTES_LENGTH: usize;

    /// TODO should be `as_bytes(&self, buf: &[u8; Self::LENGTH])`
    fn read_bytes(&self, buf: &mut [u8]);

    /// TODO should be `from_bytes(buf: &[u8; Self::LENGTH]) -> Self`
    fn from_bytes(buf: &[u8]) -> Self;
}


#[derive(Debug, Fail)]
#[non_exhaustive]
pub enum Error {
    #[fail(display = "Input/Output length does not match")]
    Length,

    #[fail(display = "Fail to pass verification")]
    VerificationFailed,
}
