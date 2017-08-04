//! Sarkara is a Post-Quantum cryptography library.

#![warn(missing_docs)]
#![feature(try_from)]

extern crate rand;
extern crate seckey;
extern crate blake2_rfc;
extern crate argon2rs;
extern crate hc256;
extern crate ascon;
extern crate newhope;
extern crate kyber;
extern crate blissb;
extern crate byteorder;

#[macro_use] pub mod utils;
pub mod hash;
pub mod pwhash;
pub mod auth;
pub mod stream;
pub mod aead;
pub mod kex;
pub mod sign;
pub mod secretbox;
pub mod sealedbox;
