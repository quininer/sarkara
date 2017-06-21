#![feature(test)]

extern crate test;
extern crate rand;
extern crate sarkara;

use test::Bencher;
use rand::{ Rng, thread_rng };
use sarkara::stream::{ HC256, StreamCipher };

macro_rules! bench_stream {
    ( $name:ident $ty:ident, $len:expr ) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let mut rng = thread_rng();
            let mut key = vec![0; $ty::KEY_LENGTH];
            let mut nonce = vec![0; $ty::NONCE_LENGTH];
            let mut data = [0; $len];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut nonce);
            rng.fill_bytes(&mut data);


            b.bytes = data.len() as u64;
            b.iter(|| $ty::new(&key).process(&nonce, &data));
        }
    }
}

bench_stream!(bench_stream_hc256_10     HC256,  10);
bench_stream!(bench_stream_hc256_1k     HC256,  1024);
bench_stream!(bench_stream_hc256_64k    HC256,  65536);
