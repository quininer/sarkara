#![feature(test)]

extern crate test;
extern crate rand;
extern crate sarkara;

use test::Bencher;
use rand::{ Rng, thread_rng };
use sarkara::aead::{ Ascon, General, RivGeneral, AeadCipher };
use sarkara::stream::HC256;
use sarkara::auth::HMAC;
use sarkara::hash::Blake2b;

type HHBB = General<HC256, HMAC<Blake2b>, Blake2b>;
type HRHB = RivGeneral<HC256, HMAC<Blake2b>, Blake2b>;


macro_rules! bench_aead {
    ( $name:ident $ty:ident, $len:expr ) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let mut rng = thread_rng();

            let mut key = vec![0; $ty::key_length()];
            let mut nonce = vec![0; $ty::nonce_length()];
            let mut data = [0; $len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut nonce);
            rng.fill_bytes(&mut data);

            b.bytes = data.len() as u64;
            b.iter(|| {
                let ciphertext = $ty::new(&key).with_aad(&nonce).encrypt(&nonce, &data);
                $ty::new(&key).with_aad(&nonce).decrypt(&nonce, &ciphertext)
            });
        }
    }
}

bench_aead!(bench_aead_ascon_10     Ascon,      10);
bench_aead!(bench_aead_ascon_1k     Ascon,      1024);
bench_aead!(bench_aead_ascon_64k    Ascon,      65536);
bench_aead!(bench_aead_hhbb_10      HHBB,       10);
bench_aead!(bench_aead_hhbb_1k      HHBB,       1024);
bench_aead!(bench_aead_hhbb_64k     HHBB,       65536);
bench_aead!(bench_aead_hrhb_10      HRHB,       10);
bench_aead!(bench_aead_hrhb_1k      HRHB,       1024);
bench_aead!(bench_aead_hrhb_64k     HRHB,       65536);
