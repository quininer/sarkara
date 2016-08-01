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

type RHCipher = General<Rabbit, HMAC<Blake2b>>;


macro_rules! bench_aead {
    (encrypt $name:ident $ty:ident ) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let (key, nonce) = (
                Bytes::random($ty::key_length()),
                Bytes::random($ty::nonce_length())
            );
            let data = rand!(bytes 4096);
            b.bytes = data.len() as u64;
            b.iter(|| $ty::new(&key).with_aad(&nonce).encrypt(&nonce, &data));
        }
    };

    (decrypt $name:ident $ty:ident ) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let (key, nonce) = (
                Bytes::random($ty::key_length()),
                Bytes::random($ty::nonce_length())
            );
            let data = rand!(bytes 4096);
            let ciphertext = $ty::new(&key).with_aad(&nonce).encrypt(&nonce, &data);
            b.bytes = ciphertext.len() as u64;
            b.iter(|| $ty::new(&key).with_aad(&nonce).decrypt(&nonce, &ciphertext));
        }
    }
}

bench_aead!(encrypt bench_aead_ascon_encrypt Ascon);
bench_aead!(decrypt bench_aead_ascon_decrypt Ascon);
bench_aead!(encrypt bench_aead_rhb_encrypt RHCipher);
bench_aead!(decrypt bench_aead_rhb_decrypt RHCipher);
