//! Sarkara is a Post-Quantum cryptography library.

#![warn(missing_docs)]
#![feature(question_mark)]

extern crate rand;
extern crate seckey;
extern crate blake2_rfc;
extern crate argon2rs;
extern crate hc256;
extern crate ascon;
extern crate newhope;
extern crate blissb;

#[macro_use] pub mod utils;
pub mod hash;
pub mod pwhash;
pub mod auth;
pub mod stream;
pub mod aead;
pub mod kex;
pub mod secretbox;
pub mod sealedbox;
pub mod sign;
