use std::ops::Deref;
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
/// let sk = PrivateKey::from(&sk_bytes[..]);
/// # let rec = NewHope::exchange(&mut keyb, &pk);
/// # NewHope::exchange_from(&mut keya, &sk, &rec);
/// # assert_eq!(keya, keyb);
/// ```
pub struct NewHope;

impl KeyExchange for NewHope {
    type PrivateKey = PrivateKey;
    type PublicKey = [u8; SENDABYTES];
    type Reconciliation = Reconciliation;

    fn sk_length() -> usize { POLY_BYTES }
    fn pk_length() -> usize { SENDABYTES }
    fn rec_length() -> usize { SENDBBYTES }

    fn keygen() -> (Self::PrivateKey, Self::PublicKey) {
        let (mut sk, mut pk) = ([0; N], [0; SENDABYTES]);
        let (mut pka, mut nonce) = ([0; N], [0; 32]);
        let mut rng = OsRng::new().unwrap().gen::<ChaChaRng>();

        rng.fill_bytes(&mut nonce);
        keygen(&mut sk, &mut pka, &nonce, rng);

        pk[..POLY_BYTES].clone_from_slice(&poly_tobytes(&pka));
        pk[POLY_BYTES..].clone_from_slice(&nonce);

        (PrivateKey(sk.into()), pk)
    }

    fn exchange(sharedkey: &mut [u8], pka: &Self::PublicKey) -> Self::Reconciliation {
        let (mut key, mut pkb, mut rec) = ([0; 32], [0; N], [0; N]);
        let (pk, nonce) = pka.split_at(POLY_BYTES);

        sharedb(
            &mut key, &mut pkb, &mut rec,
            &poly_frombytes(pk), nonce, OsRng::new().unwrap().gen::<ChaChaRng>()
        );

        sha3_256(sharedkey, &key);

        let mut output = [0; SENDBBYTES];
        output[..POLY_BYTES].clone_from_slice(&poly_tobytes(&pkb));
        output[POLY_BYTES..].clone_from_slice(&rec_tobytes(&rec));
        Reconciliation(output)
    }

    fn exchange_from(
        sharedkey: &mut [u8],
        &PrivateKey(ref sk): &Self::PrivateKey,
        &Reconciliation(ref pkb): &Self::Reconciliation
    ) {
        let mut key = [0; 32];
        let (pk, rec) = pkb.split_at(POLY_BYTES);
        shareda(&mut key, &sk[..], &poly_frombytes(pk), &rec_frombytes(rec));

        sha3_256(sharedkey, &key);
    }
}

/// Newhope private key.
pub struct PrivateKey(pub Key<[u16; N]>);

impl<'a> From<&'a [u8]> for PrivateKey {
    fn from(t: &[u8]) -> PrivateKey {
        debug_assert_eq!(t.len(), POLY_BYTES);
        PrivateKey(poly_frombytes(t).into())
    }
}

impl PrivateKey {
    /// export private key.
    pub fn export(&self) -> [u8; POLY_BYTES] {
        poly_tobytes(&self.0)
    }
}

/// Newhope reconciliation data.
pub struct Reconciliation(pub [u8; SENDBBYTES]);

impl<'a> From<&'a [u8]> for Reconciliation {
    fn from(t: &[u8]) -> Reconciliation {
        debug_assert_eq!(t.len(), SENDBBYTES);
        let mut rec = [0; SENDBBYTES];
        rec.clone_from_slice(t);
        Reconciliation(rec)
    }
}

impl Deref for Reconciliation {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
