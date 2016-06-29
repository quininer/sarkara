extern crate rand;
#[macro_use] extern crate sarkara;

use sarkara::utils::Bytes;
use sarkara::aead::{ Ascon, AeadCipher };
use sarkara::secretbox::SecretBox;


#[test]
fn seal_open_test() {
    let (key, nonce) = (
        Bytes::random(Ascon::key_length()),
        Bytes::random(Ascon::nonce_length())
    );
    let data = rand!(bytes 64);
    let ciphertext = Ascon::seal(&key, &nonce, &data);
    let plaintext = Ascon::open(&key, &nonce, &ciphertext).unwrap();

    assert_eq!(plaintext, &data[..]);

    assert!(Ascon::open(&key, &[0; 16], &ciphertext).is_err());
    assert!(Ascon::open(&key, &[0; 16], &ciphertext[1..]).is_err());
}
