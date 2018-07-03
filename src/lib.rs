//! Sarkara is a Post-Quantum cryptography library.

#![feature(non_exhaustive)]

#[macro_use] extern crate arrayref;
#[macro_use] extern crate failure;
extern crate rand;
extern crate seckey;
extern crate dilithium;
extern crate kyber;
extern crate norx;
extern crate norx_permutation;
extern crate mem_aead_mrs;

pub mod sign;
pub mod kex;
pub mod aead;
pub mod sealedbox;


pub trait Packing: Sized {
    const BYTES_LENGTH: usize;

    fn read_bytes<F: FnOnce(&[u8])>(&self, f: F);

    /// TODO should be `from_bytes(buf: &[u8; Self::LENGTH]) -> Self`
    fn from_bytes(buf: &[u8]) -> Self;
}


#[derive(Debug, Fail)]
#[non_exhaustive]
#[must_use]
pub enum Error {
    #[fail(display = "Input/Output length does not match")]
    Length,

    #[fail(display = "Fail to pass verification")]
    VerificationFailed,
}
