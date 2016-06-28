//! `Sarkara` is a cryptography library like [libsodium](https://github.com/jedisct1/libsodium),
//! use only Post-Quantum cryptography algorithms.

#![warn(missing_docs)]
#![feature(question_mark)]

extern crate rand;
extern crate blake2_rfc;
extern crate argon2rs;
extern crate hc128;
extern crate ascon;
extern crate memsec;

#[macro_use] pub mod utils;
pub mod hash;
pub mod pwhash;
pub mod auth;
pub mod stream;
pub mod aead;
