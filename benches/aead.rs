#![feature(test)]

extern crate test;
extern crate rand;
#[macro_use] extern crate sarkara;

use test::Bencher;
use sarkara::utils::Bytes;
use sarkara::aead::{ Ascon, General, AeadCipher };
use sarkara::stream::Rabbit;
use sarkara::auth::HMAC;
use sarkara::hash::Blake2b;
#[cfg(feature = "norx")] use sarkara::aead::Norx;

type RHCipher = General<Rabbit, HMAC<Blake2b>>;


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

#[bench]
fn bench_aead_rhb_encrypt(b: &mut Bencher) {
    let (key, nonce) =
        (Bytes::random(RHCipher::key_length()), Bytes::random(RHCipher::nonce_length()));
    let data = rand!(bytes 4096);
    b.bytes = data.len() as u64;
    b.iter(|| RHCipher::new(&key).with_aad(&nonce).encrypt(&nonce, &data));
}

#[bench]
fn bench_aead_rhb_decrypt(b: &mut Bencher) {
    let (key, nonce) =
        (Bytes::random(RHCipher::key_length()), Bytes::random(RHCipher::nonce_length()));
    let data = rand!(bytes 4096);
    let ciphertext = RHCipher::new(&key).with_aad(&nonce).encrypt(&nonce, &data);
    b.bytes = ciphertext.len() as u64;
    b.iter(|| RHCipher::new(&key).with_aad(&nonce).decrypt(&nonce, &ciphertext));
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
