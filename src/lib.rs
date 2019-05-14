//! Sarkara is a Post-Quantum cryptography library.

#![feature(non_exhaustive)]

#[cfg(feature = "serde")]
extern crate serde;

#[macro_use]
mod common;
pub mod aead;
pub mod kex;
pub mod sealedbox;
pub mod sign;

use failure::Fail;

pub trait Packing: Sized {
    const BYTES_LENGTH: usize;

    fn read_bytes<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T;

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
