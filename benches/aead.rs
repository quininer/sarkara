#![feature(test)]

extern crate test;
extern crate rand;
#[macro_use] extern crate sarkara;

use test::Bencher;
use sarkara::aead::{ Ascon, General, AeadCipher };
use sarkara::stream::HC256;
use sarkara::auth::HMAC;
use sarkara::hash::Blake2b;

type HHBCipher = General<HC256, HMAC<Blake2b>>;


macro_rules! bench_aead {
    ( $name:ident $ty:ident, $len:expr ) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let (key, nonce) = (
                rand!($ty::key_length()),
                rand!($ty::nonce_length())
            );
            let data = rand!(bytes $len);

            b.bytes = data.len() as u64;
            b.iter(|| {
                let ciphertext = $ty::new(&key).with_aad(&nonce).encrypt(&nonce, &data);
                $ty::new(&key).with_aad(&nonce).decrypt(&nonce, &ciphertext)
            });
        }
    }
}

bench_aead!(bench_aead_ascon_10 Ascon, 10);
bench_aead!(bench_aead_hhb_10 HHBCipher, 10);
bench_aead!(bench_aead_ascon_1k Ascon, 1024);
bench_aead!(bench_aead_hhb_1k HHBCipher, 1024);
bench_aead!(bench_aead_ascon_64k Ascon, 65536);
bench_aead!(bench_aead_hhb_64k HHBCipher, 65536);
