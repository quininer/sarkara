//! [kyber](https://eprint.iacr.org/2017/634.pdf).



use std::io;
use std::convert::TryFrom;
use rand::{ Rng, Rand, OsRng };
use seckey::Key;
use kyber::params::{ PUBLICKEYBYTES, SECRETKEYBYTES, BYTES };
use kyber::kyber;
use super::KeyExchange;


/// Kyber.
///
/// # Example(exchange)
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// use rand::ChaChaRng;
/// use sarkara::kex::{ KeyExchange, Kyber };
///
/// let (mut keya, mut keyb) = ([0; 32], [0; 32]);
/// let (sk, pk) = Kyber::keygen::<ChaChaRng>();
/// let rec = Kyber::exchange::<ChaChaRng>(&mut keyb, &pk);
/// Kyber::exchange_from(&mut keya, &sk, &rec);
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
/// # use sarkara::kex::{ KeyExchange, Kyber };
/// # let (mut keya, mut keyb) = ([0; 32], [0; 32]);
/// # let (sk, pk) = Kyber::keygen::<ChaChaRng>();
/// let sk_bytes: Vec<u8> = sk.into();
/// let sk = <Kyber as KeyExchange>::PrivateKey::try_from(&sk_bytes[..]).unwrap();
/// # let rec = Kyber::exchange::<ChaChaRng>(&mut keyb, &pk);
/// # Kyber::exchange_from(&mut keya, &sk, &rec);
/// # assert_eq!(keya, keyb);
/// # }
/// ```
pub struct Kyber;

impl KeyExchange for Kyber {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Reconciliation = Reconciliation;

    const SK_LENGTH: usize = SECRETKEYBYTES;
    const PK_LENGTH: usize = PUBLICKEYBYTES;
    const REC_LENGTH: usize = BYTES;

    fn keygen<R: Rand + Rng>() -> (Self::PrivateKey, Self::PublicKey) {
        let (mut sk, mut pk) = (Key::from([0; SECRETKEYBYTES]), [0; PUBLICKEYBYTES]);
        let mut rng = OsRng::new().unwrap().gen::<R>();

        kyber::keypair(&mut rng, &mut pk, &mut *sk);

        (PrivateKey(sk), PublicKey(pk))
    }

    fn exchange<R: Rand + Rng>(sharedkey: &mut [u8], &PublicKey(ref pka): &Self::PublicKey) -> Self::Reconciliation {
        let mut rec = [0; BYTES];
        let mut key = Key::from([0u8; 32]);
        let mut rng = OsRng::new().unwrap().gen::<R>();

        kyber::enc(&mut rng, &mut rec, &mut key, pka);
        sharedkey[..32].copy_from_slice(&*key); // TODO should be hash ?

        Reconciliation(rec)
    }

    fn exchange_from(
        sharedkey: &mut [u8],
        &PrivateKey(ref sk): &Self::PrivateKey,
        &Reconciliation(ref rec): &Self::Reconciliation
    ) {
        let mut key = Key::from([0u8; 32]);
        kyber::dec(&mut key, rec, &sk[..]);
        sharedkey[..32].copy_from_slice(&*key);
    }
}


new_type!(
    /// Kyber private key.
    pub struct PrivateKey(pub Key<[u8; SECRETKEYBYTES]>);
    from: (input) {
        if input.len() == SECRETKEYBYTES {
            let mut sk = [0; SECRETKEYBYTES];
            sk.copy_from_slice(input);
            Ok(PrivateKey(Key::from(sk)))
        } else {
            err!(InvalidInput, "PrivateKey: invalid input length.")
        }
    },
    into: (self) -> Vec<u8> {
        let PrivateKey(ref input) = self;
        Vec::from(&input[..])
    }
);

new_type!(
    /// Kyber public key.
    pub struct PublicKey(pub [u8; PUBLICKEYBYTES]);
    from: (input) {
        if input.len() == PUBLICKEYBYTES {
            let mut pk = [0; PUBLICKEYBYTES];
            pk.clone_from_slice(input);
            Ok(PublicKey(pk))
        } else {
            err!(InvalidInput, "PublicKey: invalid input length.")
        }
    },
    into: (self) -> Vec<u8> {
        let PublicKey(ref input) = self;
        Vec::from(input as &[u8])
    }
);

new_type!(
    /// Kyber reconciliation data.
    pub struct Reconciliation(pub [u8; BYTES]);
    from: (input) {
        if input.len() == BYTES {
            let mut rec = [0; BYTES];
            rec.clone_from_slice(input);
            Ok(Reconciliation(rec))
        } else {
            err!(InvalidInput, "Reconciliation: invalid input length.")
        }
    },
    into: (self) -> Vec<u8> {
        let Reconciliation(ref input) = self;
        Vec::from(input as &[u8])
    }
);
