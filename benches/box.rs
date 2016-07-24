#![feature(test)]

extern crate test;
extern crate rand;
#[macro_use] extern crate sarkara;

use test::Bencher;
use sarkara::utils::Bytes;
use sarkara::kex::{ NewHope, KeyExchange };
use sarkara::aead::{ Ascon, AeadCipher };
#[cfg(feature = "norx")] use sarkara::aead::Norx;


#[bench]
fn bench_secretbox_ascon_encrypt(b: &mut Bencher) {
    use sarkara::secretbox::SecretBox;

    let key = Bytes::random(Ascon::key_length());
    let data = rand!(bytes 4096);
    b.bytes = data.len() as u64;
    b.iter(|| Ascon::seal(&key, &data));
}

#[bench]
fn bench_secretbox_ascon_decrypt(b: &mut Bencher) {
    use sarkara::secretbox::SecretBox;

    let key = Bytes::random(Ascon::key_length());
    let data = rand!(bytes 4096);
    let ciphertext = Ascon::seal(&key, &data);
    b.bytes = ciphertext.len() as u64;
    b.iter(|| Ascon::open(&key, &ciphertext));
}

#[cfg(feature = "norx")]
#[bench]
fn bench_secretbox_norx_encrypt(b: &mut Bencher) {
    use sarkara::secretbox::SecretBox;

    let key = Bytes::random(Norx::key_length());
    let data = rand!(bytes 4096);
    b.bytes = data.len() as u64;
    b.iter(|| Norx::seal(&key, &data));
}

#[cfg(feature = "norx")]
#[bench]
fn bench_secretbox_norx_decrypt(b: &mut Bencher) {
    use sarkara::secretbox::SecretBox;

    let key = Bytes::random(Norx::key_length());
    let data = rand!(bytes 4096);
    let ciphertext = Norx::seal(&key, &data);
    b.bytes = ciphertext.len() as u64;
    b.iter(|| Norx::open(&key, &ciphertext));
}

#[bench]
fn bench_sealedbox_ascon_encrypt(b: &mut Bencher) {
    use sarkara::sealedbox::SealedBox;

    let (_, pk) = NewHope::keygen();
    let data = rand!(bytes 4096);
    b.bytes = data.len() as u64;
    b.iter(|| Ascon::seal::<NewHope>(&pk, &data));
}

#[bench]
fn bench_sealedbox_ascon_decrypt(b: &mut Bencher) {
    use sarkara::sealedbox::SealedBox;

    let (sk, pk) = NewHope::keygen();
    let data = rand!(bytes 4096);
    let ciphertext = Ascon::seal::<NewHope>(&pk, &data);
    b.bytes = ciphertext.len() as u64;
    b.iter(|| Ascon::open::<NewHope>(&sk, &ciphertext));
}

#[cfg(feature = "norx")]
#[bench]
fn bench_sealedbox_norx_encrypt(b: &mut Bencher) {
    use sarkara::sealedbox::SealedBox;

    let (_, pk) = NewHope::keygen();
    let data = rand!(bytes 4096);
    b.bytes = data.len() as u64;
    b.iter(|| Norx::seal::<NewHope>(&pk, &data));
}

#[cfg(feature = "norx")]
#[bench]
fn bench_sealedbox_norx_decrypt(b: &mut Bencher) {
    use sarkara::sealedbox::SealedBox;

    let (sk, pk) = NewHope::keygen();
    let data = rand!(bytes 4096);
    let ciphertext = Norx::seal::<NewHope>(&pk, &data);
    b.bytes = ciphertext.len() as u64;
    b.iter(|| Norx::open::<NewHope>(&sk, &ciphertext));
}
