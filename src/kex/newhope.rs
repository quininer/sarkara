//! [newhope](https://eprint.iacr.org/2015/1092).

use std::io;
use std::convert::TryFrom;
use seckey::Key;
use rand::{ Rand, Rng, OsRng };
use newhope::{
    N, POLY_BYTES, SENDABYTES, SENDBBYTES,
    poly_frombytes, poly_tobytes,
    rec_frombytes, rec_tobytes,
    keygen, sharedb, shareda,
    sha3_256
};
use super::KeyExchange;


/// Newhope key exchange.
///
/// # Example(exchange)
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// use rand::ChaChaRng;
/// use sarkara::kex::{ KeyExchange, NewHope };
///
/// let (mut keya, mut keyb) = ([0; 32], [0; 32]);
/// let (sk, pk) = NewHope::keygen::<ChaChaRng>();
/// let rec = NewHope::exchange::<ChaChaRng>(&mut keyb, &pk);
/// NewHope::exchange_from(&mut keya, &sk, &rec);
///
/// assert_eq!(keya, keyb);
/// # }
/// ```
///
/// # Example(import/export)
/// ```
/// # #![feature(try_from)]
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// # use std::convert::TryFrom;
/// # use rand::ChaChaRng;
/// # use sarkara::kex::{ KeyExchange, NewHope };
/// # let (mut keya, mut keyb) = ([0; 32], [0; 32]);
/// # let (sk, pk) = NewHope::keygen::<ChaChaRng>();
/// let sk_bytes: Vec<u8> = sk.into();
/// let sk = <NewHope as KeyExchange>::PrivateKey::try_from(&sk_bytes[..]).unwrap();
/// # let rec = NewHope::exchange::<ChaChaRng>(&mut keyb, &pk);
/// # NewHope::exchange_from(&mut keya, &sk, &rec);
/// # assert_eq!(keya, keyb);
/// # }
/// ```
pub struct NewHope;

impl KeyExchange for NewHope {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Reconciliation = Reconciliation;

    #[inline] fn sk_length() -> usize { POLY_BYTES }
    #[inline] fn pk_length() -> usize { SENDABYTES }
    #[inline] fn rec_length() -> usize { SENDBBYTES }

    fn keygen<R: Rand + Rng>() -> (Self::PrivateKey, Self::PublicKey) {
        let (mut sk, mut pk) = ([0; N].into(), [0; SENDABYTES]);

        {
            let Key(ref mut sk) = sk;
            let mut pka = [0; N];
            let mut rng = OsRng::new().unwrap().gen::<R>();

            rng.fill_bytes(&mut pk[POLY_BYTES..]);
            keygen(sk, &mut pka, &pk[POLY_BYTES..], rng);

            pk[..POLY_BYTES].clone_from_slice(&poly_tobytes(&pka));
        }

        (PrivateKey(sk), PublicKey(pk))
    }

    fn exchange<R: Rand + Rng>(sharedkey: &mut [u8], &PublicKey(ref pka): &Self::PublicKey) -> Self::Reconciliation {
        let (Key(mut key), mut pkb, mut rec) = ([0; 32].into(), [0; N], [0; N]);
        let (pk, nonce) = pka.split_at(POLY_BYTES);

        sharedb(
            &mut key, &mut pkb, &mut rec,
            &poly_frombytes(pk), nonce, OsRng::new().unwrap().gen::<R>()
        );

        sha3_256(sharedkey, &key);

        let mut output = [0; SENDBBYTES];
        output[..POLY_BYTES].clone_from_slice(&poly_tobytes(&pkb));
        output[POLY_BYTES..].clone_from_slice(&rec_tobytes(&rec));
        Reconciliation(output)
    }

    fn exchange_from(
        sharedkey: &mut [u8],
        &PrivateKey(Key(ref sk)): &Self::PrivateKey,
        &Reconciliation(ref pk): &Self::Reconciliation
    ) {
        let Key(mut key) = [0; 32].into();
        let (pkb, rec) = pk.split_at(POLY_BYTES);
        shareda(&mut key, sk, &poly_frombytes(pkb), &rec_frombytes(rec));

        sha3_256(sharedkey, &key);
    }
}


new_type!(
    /// Newhope private key.
    pub struct PrivateKey(pub Key<[u16; N]>);
    from: (input) {
        if input.len() == POLY_BYTES {
            Ok(PrivateKey(poly_frombytes(input).into()))
        } else {
            err!(InvalidInput, "PrivateKey: invalid input length.")
        }
    },
    into: (self) -> Vec<u8> {
        let PrivateKey(Key(ref input)) = self;
        Vec::from(&poly_tobytes(input)[..])
    }
);

new_type!(
    /// Newhope public key.
    pub struct PublicKey(pub [u8; SENDABYTES]);
    from: (input) {
        if input.len() == SENDABYTES {
            let mut pk = [0; SENDABYTES];
            pk.clone_from_slice(input);
            Ok(PublicKey(pk))
        } else {
            err!(InvalidInput, "PublicKey: invalid input length.")
        }
    },
    into: (self) -> Vec<u8> {
        let PublicKey(ref input) = self;
        Vec::from(&input[..])
    }
);

new_type!(
    /// Newhope reconciliation data.
    pub struct Reconciliation(pub [u8; SENDBBYTES]);
    from: (input) {
        if input.len() == SENDBBYTES {
            let mut rec = [0; SENDBBYTES];
            rec.clone_from_slice(input);
            Ok(Reconciliation(rec))
        } else {
            err!(InvalidInput, "Reconciliation: invalid input length.")
        }
    },
    into: (self) -> Vec<u8> {
        let Reconciliation(ref input) = self;
        Vec::from(&input[..])
    }
);
