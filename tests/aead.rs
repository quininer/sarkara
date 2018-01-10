extern crate rand;
extern crate sarkara;

use std::thread;
use std::sync::mpsc::channel;
use rand::{ Rng, thread_rng };
use sarkara::aead::{ AeadCipher, Online, Encryption, Decryption };
use sarkara::aead::sparx256colm0::Sparx256Colm0;


fn test_aead<AE: AeadCipher>() {
    let mut key = vec![0; AE::KEY_LENGTH];
    let mut nonce = vec![0; AE::NONCE_LENGTH];

    for i in 1..65 {
        let mut aad = vec![0; thread_rng().gen_range(0, 34)];

        let mut pt = vec![0; i];
        let mut ct = vec![0; pt.len() + AE::TAG_LENGTH];
        let mut ot = vec![0; pt.len()];

        thread_rng().fill_bytes(&mut key);
        thread_rng().fill_bytes(&mut nonce);
        thread_rng().fill_bytes(&mut pt);

        let cipher = AE::new(&key);
        cipher.seal(&nonce, &aad, &pt, &mut ct).unwrap();
        let r = cipher.open(&nonce, &aad, &ct, &mut ot).unwrap();
        assert!(r);
        assert_eq!(pt, ot);
    }
}

fn test_onlineae<AE>()
    where
        for<'a> AE: AeadCipher + Online<'a>
{
    let mut key = vec![0; AE::KEY_LENGTH];
    let mut nonce = vec![0; AE::NONCE_LENGTH];

    for i in 1..65 {
        let mut aad = vec![0; thread_rng().gen_range(0, 34)];
        let mut pt = vec![0; i];
        thread_rng().fill_bytes(&mut key);
        thread_rng().fill_bytes(&mut nonce);
        thread_rng().fill_bytes(&mut pt);

        let (send, recv) = channel();

        let key2 = key.clone();
        let nonce2 = nonce.clone();
        let aad2 = aad.clone();
        let pt2 = pt.clone();
        let a = thread::spawn(move || {
            let cipher = AE::new(&key2);
            let mut process = cipher.encrypt(&nonce2, &aad2);

            let mut ctpos = 0;
            let mut ct = vec![0; pt2.len() + AE::TAG_LENGTH];
            let mut buf = Vec::new();

            if let Err(remaining) = process.process(&pt2, &mut ct) {
                ctpos += pt2.len() - remaining.len();
                buf.extend_from_slice(remaining);
            } else {
                ctpos += pt2.len();
            }
            let (ct, ct2) = ct.split_at_mut(ctpos);
            send.send(Vec::from(ct)).unwrap();

            process.finalize(&buf, ct2).unwrap();
            send.send(Vec::from(ct2)).unwrap();
        });

        let key2 = key.clone();
        let nonce2 = nonce.clone();
        let aad2 = aad.clone();
        let b = thread::spawn(move || {
            let cipher = AE::new(&key2);
            let mut process = cipher.decrypt(&nonce2, &aad2);

            let mut otpos = 0;
            let mut ot = vec![0; i];
            let mut buf = Vec::new();

            let ct = recv.recv().unwrap();
            if let Err(remaining) = process.process(&ct, &mut ot) {
                otpos += ct.len() - remaining.len();
                buf.extend_from_slice(remaining);
            } else {
                otpos += ct.len();
            }

            let ct2 = recv.recv().unwrap();
            buf.extend_from_slice(&ct2);
            let r = process.finalize(&buf, &mut ot[otpos..]).unwrap();

            assert!(r);
            assert_eq!(ot, pt);
        });

        a.join().unwrap();
        b.join().unwrap();
    }
}


#[test]
fn test_sparx256colm0() {
    test_aead::<Sparx256Colm0>();
    test_onlineae::<Sparx256Colm0>();
}
