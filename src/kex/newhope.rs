use std::ops::Deref;
use rand::{ Rng, OsRng, ChaChaRng };
use newhope::{
    N, POLY_BYTES, SENDABYTES, SENDBBYTES,
    poly_frombytes, poly_tobytes,
    rec_frombytes, rec_tobytes,
    keygen, sharedb, shareda,
    sha3_256
};
use super::KeyExchange;


pub struct NewHope;

pub struct PrivateKey(pub [u16; N]);

impl PrivateKey {
    pub fn import(input: &[u8]) -> PrivateKey {
        PrivateKey(poly_frombytes(input))
    }

    pub fn export(&self) -> [u8; POLY_BYTES] {
        poly_tobytes(&self.0)
    }
}

impl KeyExchange for NewHope {
    type PrivateKey = PrivateKey;
    type PublicKey = [u8; SENDABYTES];
    type Reconciliation = [u8; SENDBBYTES];

    fn keygen() -> (Self::PrivateKey, Self::PublicKey) {
        let (mut sk, mut pk) = ([0; N], [0; SENDABYTES]);
        let (mut pka, mut nonce) = ([0; N], [0; 32]);
        let mut rng = OsRng::new().unwrap().gen::<ChaChaRng>();

        rng.fill_bytes(&mut nonce);
        keygen(&mut sk, &mut pka, &nonce, rng);

        pk[..POLY_BYTES].clone_from_slice(&poly_tobytes(&pka));
        pk[POLY_BYTES..].clone_from_slice(&nonce);

        (PrivateKey(sk), pk)
    }

    fn exchange(sharedkey: &mut [u8], pka: &Self::PublicKey) -> Self::Reconciliation {
        let mut output = [0; SENDBBYTES];
        let (mut key, mut pkb, mut c) = ([0; N], [0; N], [0; N]);
        let (pk, nonce) = pka.split_at(POLY_BYTES);

        sharedb(
            &mut key, &mut pkb, &mut c,
            &poly_frombytes(pk), nonce, OsRng::new().unwrap().gen::<ChaChaRng>()
        );

        sha3_256(sharedkey, &key);

        output[..POLY_BYTES].clone_from_slice(&poly_tobytes(&pkb));
        output[POLY_BYTES..].clone_from_slice(&rec_tobytes(&c));
        output
    }

    fn exchange_from(sharedkey: &mut [u8], &PrivateKey(ref sk): &Self::PrivateKey, pkb: &Self::Reconciliation) {
        let mut key = [0; N];
        let (pk, rec) = pkb.split_at(POLY_BYTES);
        shareda(&mut key, sk, &poly_frombytes(pk), &rec_frombytes(rec));

        sha3_256(sharedkey, &key);
    }
}
