#![feature(test)]

extern crate test;
extern crate rand;
#[macro_use] extern crate sarkara;

use test::Bencher;
use sarkara::utils::Bytes;
use sarkara::aead::{ Ascon, AeadCipher };
#[cfg(feature = "norx")] use sarkara::aead::Norx;


#[bench]
fn bench_aead_ascon_encrypt(b: &mut Bencher) {
    let (key, nonce) =
        (Bytes::random(Ascon::key_length()), Bytes::random(Ascon::nonce_length()));
    let data = rand!(bytes 4096);
    b.bytes = data.len() as u64;
    b.iter(|| Ascon::new(&key).with_aad(&nonce).encrypt(&nonce, &data));
}

#[bench]
fn bench_aead_ascon_decrypt(b: &mut Bencher) {
    let (key, nonce) =
        (Bytes::random(Ascon::key_length()), Bytes::random(Ascon::nonce_length()));
    let data = rand!(bytes 4096);
    let ciphertext = Ascon::new(&key).with_aad(&nonce).encrypt(&nonce, &data);
    b.bytes = ciphertext.len() as u64;
    b.iter(|| Ascon::new(&key).with_aad(&nonce).decrypt(&nonce, &ciphertext));
}

#[cfg(feature = "norx")]
#[bench]
fn bench_aead_norx_encrypt(b: &mut Bencher) {
    let (key, nonce) =
        (Bytes::random(Norx::key_length()), Bytes::random(Norx::nonce_length()));
    let data = rand!(bytes 4096);
    b.bytes = data.len() as u64;
    b.iter(|| Norx::new(&key).with_aad(&nonce).encrypt(&nonce, &data));
}

#[cfg(feature = "norx")]
#[bench]
fn bench_aead_norx_decrypt(b: &mut Bencher) {
    let (key, nonce) =
        (Bytes::random(Norx::key_length()), Bytes::random(Norx::nonce_length()));
    let data = rand!(bytes 4096);
    let ciphertext = Norx::new(&key).with_aad(&nonce).encrypt(&nonce, &data);
    b.bytes = ciphertext.len() as u64;
    b.iter(|| Norx::new(&key).with_aad(&nonce).decrypt(&nonce, &ciphertext));
}
