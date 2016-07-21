extern crate rand;
#[macro_use] extern crate sarkara;

use sarkara::utils::Bytes;
use sarkara::aead::{ Ascon, AeadCipher };
use sarkara::secretbox::SecretBox;


#[test]
fn seal_open_test() {
    let key = Bytes::random(Ascon::key_length());
    let data = rand!(bytes 64);
    let ciphertext = Ascon::seal(&key, &data);
    let plaintext = Ascon::open(&key, &ciphertext).unwrap();

    assert_eq!(plaintext, &data[..]);
    assert!(Ascon::open(&key, &ciphertext[..ciphertext.len()-1]).is_err());
    assert!(Ascon::open(&key, &ciphertext[1..]).is_err());
}
