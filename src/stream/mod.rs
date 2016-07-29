//! Secret-key encryption.
//!
//! Sarkara use [`Rabbit`](http://www.ecrypt.eu.org/stream/rabbitpf.html),
//! it is one of [`eSTREAM`](http://www.ecrypt.eu.org/stream/) portfolio,
//! have good design and performance.

mod rabbit;

pub use self::rabbit::Rabbit;


/// `StreamCipher` trait.
pub trait StreamCipher {
    /// Create a new StreamCipher.
    fn new(key: &[u8]) -> Self;

    /// Process data.
    fn process(&mut self, nonce: &[u8], data: &[u8]) -> Vec<u8>;
}
