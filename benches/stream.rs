#![feature(test)]

extern crate test;
extern crate rand;
#[macro_use] extern crate sarkara;

use test::Bencher;
use sarkara::utils::Bytes;
use sarkara::stream::{ HC256, StreamCipher };

macro_rules! bench_stream {
    ( $name:ident $ty:ident, $len:expr ) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let (key, nonce) = (
                Bytes::random($ty::key_length()),
                Bytes::random($ty::nonce_length())
            );
            let data = rand!(bytes $len);
            b.bytes = data.len() as u64;
            b.iter(|| $ty::new(&key).process(&nonce, &data));
        }
    }
}

bench_stream!(bench_stream_hc256_10 HC256, 10);
bench_stream!(bench_stream_hc256_1k HC256, 1024);
bench_stream!(bench_stream_hc256_64k HC256, 65536);
