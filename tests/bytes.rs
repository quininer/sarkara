extern crate sarkara;

use sarkara::utils::Bytes;


#[test]
fn bytes_eq_test() {
    let x = Bytes::new(&[3; 16]);
    let y = Bytes::new(&[2; 16]);
    let z = [3; 16];

    assert!(x != y);
    assert_eq!(x, z);
    assert_eq!(x, Bytes::new(&z));
    assert!(x != Bytes::new(&y));
}
