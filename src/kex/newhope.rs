use seckey::Key;
use rand::{ Rng, OsRng, ChaChaRng };
use newhope::{
    N, POLY_BYTES, SENDABYTES, SENDBBYTES,
    poly_frombytes, poly_tobytes,
    rec_frombytes, rec_tobytes,
    keygen, sharedb, shareda,
    sha3_256
};
use super::KeyExchange;


/// Newhope key exchange..
///
/// # Example(exchange)
/// ```
/// use sarkara::kex::{ KeyExchange, NewHope };
///
/// let (mut keya, mut keyb) = ([0; 32], [0; 32]);
/// let (sk, pk) = NewHope::keygen();
/// let rec = NewHope::exchange(&mut keyb, &pk);
/// NewHope::exchange_from(&mut keya, &sk, &rec);
///
/// assert_eq!(keya, keyb);
/// ```
///
/// # Example(import/export)
/// ```
/// # use sarkara::kex::{ KeyExchange, PrivateKey, NewHope };
/// # let (mut keya, mut keyb) = ([0; 32], [0; 32]);
/// # let (sk, pk) = NewHope::keygen();
/// let sk_bytes = sk.export();
/// let sk = PrivateKey::import(&sk_bytes);
/// # let rec = NewHope::exchange(&mut keyb, &pk);
/// # NewHope::exchange_from(&mut keya, &sk, &rec);
/// # assert_eq!(keya, keyb);
/// ```
pub struct NewHope;

impl KeyExchange for NewHope {
    type PrivateKey = PrivateKey;

    fn sk_length() -> usize { POLY_BYTES }
    fn pk_length() -> usize { SENDABYTES }
    fn rec_length() -> usize { SENDBBYTES }

    fn keygen() -> (Self::PrivateKey, Vec<u8>) {
        let (mut sk, mut pk) = ([0; N], vec![0; SENDABYTES]);
        let (mut pka, mut nonce) = ([0; N], [0; 32]);
        let mut rng = OsRng::new().unwrap().gen::<ChaChaRng>();

        rng.fill_bytes(&mut nonce);
        keygen(&mut sk, &mut pka, &nonce, rng);

        pk[..POLY_BYTES].clone_from_slice(&poly_tobytes(&pka));
        pk[POLY_BYTES..].clone_from_slice(&nonce);

        (PrivateKey(sk.into()), pk)
    }

    fn exchange(sharedkey: &mut [u8], pka: &[u8]) -> Vec<u8> {
        debug_assert_eq!(pka.len(), Self::pk_length());

        let (mut key, mut pkb, mut rec) = ([0; 32], [0; N], [0; N]);
        let (pk, nonce) = pka.split_at(POLY_BYTES);

        sharedb(
            &mut key, &mut pkb, &mut rec,
            &poly_frombytes(pk), nonce, OsRng::new().unwrap().gen::<ChaChaRng>()
        );

        sha3_256(sharedkey, &key);

        let mut output = Vec::with_capacity(Self::rec_length());
        output.extend_from_slice(&poly_tobytes(&pkb));
        output.extend_from_slice(&rec_tobytes(&rec));
        output
    }

    fn exchange_from(sharedkey: &mut [u8], &PrivateKey(ref sk): &Self::PrivateKey, pkb: &[u8]) {
        debug_assert_eq!(pkb.len(), Self::rec_length());

        let mut key = [0; 32];
        let (pk, rec) = pkb.split_at(POLY_BYTES);
        shareda(&mut key, &sk[..], &poly_frombytes(pk), &rec_frombytes(rec));

        sha3_256(sharedkey, &key);
    }
}

/// Newhope private key.
pub struct PrivateKey(pub Key<[u16; N]>);

impl PrivateKey {
    /// import private key.
    pub fn import(input: &[u8]) -> PrivateKey {
        PrivateKey(poly_frombytes(input).into())
    }

    /// export private key.
    pub fn export(&self) -> [u8; POLY_BYTES] {
        poly_tobytes(&self.0)
    }
}
