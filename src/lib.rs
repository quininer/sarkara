//! Sarkara is a Post-Quantum cryptography library.

#[macro_use] extern crate arrayref;
extern crate rand;
extern crate seckey;
extern crate dilithium;
extern crate kyber;

pub mod sign;
pub mod kex;


pub trait Packing: Sized {
    const LENGTH: usize;

    /// TODO shouldbe `as_bytes(&self, buf: &[u8; Self::LENGTH])`
    fn read_bytes(&self, buf: &mut [u8]);

    /// TODO shouldbe `from_bytes(buf: &[u8; Self::LENGTH]) -> Self`
    fn from_bytes(buf: &[u8]) -> Option<Self>;
}
