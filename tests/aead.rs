extern crate rand;
extern crate sarkara;

use std::thread;
use std::sync::mpsc::channel;
use rand::{ Rng, RngCore, FromEntropy, ChaChaRng };
use sarkara::Error;
use sarkara::aead::{ AeadCipher, Online, Encryption, Decryption };
use sarkara::aead::norx6441::Norx6441;


fn test_aead<AE: AeadCipher>() {
    let mut key = vec![0u8; AE::KEY_LENGTH];
    let mut nonce = vec![0u8; AE::NONCE_LENGTH];
    let mut rng = ChaChaRng::from_entropy();

    for i in 1..256 {
        let mut aad = vec![0u8; rng.gen_range(0, 34)];
        let mut pt = vec![0u8; i];
        let mut ct = vec![0u8; pt.len() + AE::TAG_LENGTH];
        let mut ot = vec![0u8; pt.len()];

        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut aad);
        rng.fill_bytes(&mut pt);

        let cipher = AE::new(&key);
        cipher.seal(&nonce, &aad, &pt, &mut ct).unwrap();
        cipher.open(&nonce, &aad, &ct, &mut ot).unwrap();

        assert_eq!(pt, ot);

        ct[i - 1] ^= 0x42;
        assert!(if let Err(Error::VerificationFailed) = cipher.open(&nonce, &aad, &ct, &mut ot) {
            true
        } else {
            false
        });
    }
}

fn test_onlineae<AE>()
    where
        for<'a> AE: AeadCipher + Online<'a>
{
    let mut key = vec![0u8; AE::KEY_LENGTH];
    let mut nonce = vec![0u8; AE::NONCE_LENGTH];
    let mut rng = ChaChaRng::from_entropy();

    for i in 1..256 {
        let mut aad = vec![0u8; rng.gen_range(0, 34)];
        let mut pt = vec![0u8; i];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut pt);

        let (send, recv) = channel();

        let key2 = key.clone();
        let nonce2 = nonce.clone();
        let aad2 = aad.clone();
        let pt2 = pt.clone();
        let a = thread::spawn(move || {
            let cipher = AE::new(&key2);
            let mut process = cipher.encrypt(&nonce2, &aad2);

            let mut ct = vec![0u8; pt2.len() + AE::TAG_LENGTH];
            let mut buf = Vec::new();

            let ct1_len = process.process(&pt2, &mut ct).len();
            buf.extend_from_slice(&pt2[ct1_len..]);
            let (ct1, ct2) = ct.split_at_mut(ct1_len);
            send.send(Vec::from(ct1)).unwrap();

            process.finalize(&buf, ct2).unwrap();
            send.send(Vec::from(ct2)).unwrap();
        });

        let key2 = key.clone();
        let nonce2 = nonce.clone();
        let aad2 = aad.clone();
        let b = thread::spawn(move || {
            let cipher = AE::new(&key2);
            let mut process = cipher.decrypt(&nonce2, &aad2);

            let mut ot = vec![0u8; i];
            let mut buf = Vec::new();

            let ct1 = recv.recv().unwrap();
            let ot1_len = process.process(&ct1, &mut ot).len();
            buf.extend_from_slice(&ct1[ot1_len..]);

            let ct2 = recv.recv().unwrap();
            buf.extend_from_slice(&ct2);
            process.finalize(&buf, &mut ot[ot1_len..]).unwrap();

            assert_eq!(ot, pt);
        });

        a.join().unwrap();
        b.join().unwrap();
    }
}


#[test]
fn test_norx6441() {
    test_aead::<Norx6441>();
    test_onlineae::<Norx6441>();
}
