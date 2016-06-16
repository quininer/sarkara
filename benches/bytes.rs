#![feature(test)]

extern crate test;
extern crate sarkara;

use test::Bencher;
use sarkara::utils::Bytes;


#[bench]
fn bytes_eq_bench(b: &mut Bencher) {
    let x = Bytes::new(&[9; 1024]);
    let y = Bytes::new(&[9; 1024]);

    b.iter(|| x == y);
}

#[bench]
fn bytes_nq_bench(b: &mut Bencher) {
    let x = Bytes::new(&[8; 1024]);
    let z = Bytes::new(&[3; 1024]);

    b.iter(|| x != z);
}
