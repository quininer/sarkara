#![feature(test)]

extern crate test;
extern crate rand;
#[macro_use] extern crate sarkara;

use test::Bencher;
use sarkara::utils::Bytes;
use sarkara::kex::{ NewHope, KeyExchange };
use sarkara::aead::{ Ascon, General, AeadCipher };
use sarkara::stream::Rabbit;
use sarkara::auth::HMAC;
use sarkara::hash::Blake2b;

type RHCipher = General<Rabbit, HMAC<Blake2b>>;


macro_rules! bench_box {
    (secretbox encrypt $name:ident $ty:ident ) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            use sarkara::secretbox::SecretBox;

            let key = Bytes::random($ty::key_length());
            let data = rand!(bytes 4096);
            b.bytes = data.len() as u64;
            b.iter(|| $ty::seal(&key, &data));
        }
    };
    (secretbox decrypt $name:ident $ty:ident ) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            use sarkara::secretbox::SecretBox;

            let key = Bytes::random($ty::key_length());
            let data = rand!(bytes 4096);
            let ciphertext = $ty::seal(&key, &data);
            b.bytes = ciphertext.len() as u64;
            b.iter(|| $ty::open(&key, &ciphertext));
        }
    };
    (sealedbox encrypt $name:ident $kty:ident $cty:ident ) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            use sarkara::sealedbox::SealedBox;

            let (_, pk) = $kty::keygen();
            let data = rand!(bytes 4096);
            b.bytes = data.len() as u64;
            b.iter(|| $cty::seal::<$kty>(&pk, &data));
        }
    };
    (sealedbox decrypt $name:ident $kty:ident $cty:ident ) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            use sarkara::sealedbox::SealedBox;

            let (sk, pk) = $kty::keygen();
            let data = rand!(bytes 4096);
            let ciphertext = $cty::seal::<$kty>(&pk, &data);
            b.bytes = ciphertext.len() as u64;
            b.iter(|| $cty::open::<$kty>(&sk, &ciphertext));
        }
    }
}

bench_box!(secretbox encrypt bench_secretbox_ascon_encrypt Ascon);
bench_box!(secretbox decrypt bench_secretbox_ascon_decrypt Ascon);
bench_box!(sealedbox encrypt bench_sealedbox_ascon_encrypt NewHope Ascon);
bench_box!(sealedbox decrypt bench_sealedbox_ascon_decrypt NewHope Ascon);

bench_box!(secretbox encrypt bench_secretbox_rhb_encrypt RHCipher);
bench_box!(secretbox decrypt bench_secretbox_rhb_decrypt RHCipher);
bench_box!(sealedbox encrypt bench_sealedbox_rhb_encrypt NewHope RHCipher);
bench_box!(sealedbox decrypt bench_sealedbox_rhb_decrypt NewHope RHCipher);
