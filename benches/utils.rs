#![feature(test)]

extern crate test;
extern crate rand;
#[macro_use] extern crate sarkara;

use test::Bencher;


#[bench]
fn bench_rand_bytes(b: &mut Bencher) {
    b.iter(|| rand!(bytes 1024));
}

#[bench]
fn bench_rand_vec(b: &mut Bencher) {
    b.iter(|| {
        let _: Vec<u8> = rand!(1024);
    })
}
