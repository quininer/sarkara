use std::io;
use std::convert::TryFrom;
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
/// # #![feature(try_from)]
/// # use std::convert::TryFrom;
/// # use sarkara::kex::{ KeyExchange, PrivateKey, NewHope };
/// # let (mut keya, mut keyb) = ([0; 32], [0; 32]);
/// # let (sk, pk) = NewHope::keygen();
/// let sk_bytes: Vec<u8> = sk.into();
/// let sk = PrivateKey::try_from(&sk_bytes[..]).unwrap();
/// # let rec = NewHope::exchange(&mut keyb, &pk);
/// # NewHope::exchange_from(&mut keya, &sk, &rec);
/// # assert_eq!(keya, keyb);
/// ```
pub struct NewHope;

impl KeyExchange for NewHope {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Reconciliation = Reconciliation;

    #[inline] fn sk_length() -> usize { POLY_BYTES }
    #[inline] fn pk_length() -> usize { SENDABYTES }
    #[inline] fn rec_length() -> usize { SENDBBYTES }

    fn keygen() -> (Self::PrivateKey, Self::PublicKey) {
        let (mut sk, mut pk) = ([0; N], [0; SENDABYTES]);
        let (mut pka, mut nonce) = ([0; N], [0; 32]);
        let mut rng = OsRng::new().unwrap().gen::<ChaChaRng>();

        rng.fill_bytes(&mut nonce);
        keygen(&mut sk, &mut pka, &nonce, rng);

        pk[..POLY_BYTES].clone_from_slice(&poly_tobytes(&pka));
        pk[POLY_BYTES..].clone_from_slice(&nonce);

        (PrivateKey(sk.into()), PublicKey(pk))
    }

    fn exchange(sharedkey: &mut [u8], &PublicKey(ref pka): &Self::PublicKey) -> Self::Reconciliation {
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

impl<'a> TryFrom<&'a [u8]> for PrivateKey {
    type Err = io::Error;
    fn try_from(input: &[u8]) -> io::Result<Self> {
        if input.len() == POLY_BYTES {
            Ok(PrivateKey(poly_frombytes(input).into()))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid input length."
            ))
        }
    }
}

impl From<PrivateKey> for Vec<u8> {
    fn from(PrivateKey(sk): PrivateKey) -> Vec<u8> {
        Vec::from(&poly_tobytes(&sk)[..])
    }
}

/// Newhope public key.
pub struct PublicKey(pub [u8; SENDABYTES]);

impl<'a> TryFrom<&'a [u8]> for PublicKey {
    type Err = io::Error;
    fn try_from(input: &[u8]) -> io::Result<Self> {
        if input.len() == SENDABYTES {
            let mut pk = [0; SENDABYTES];
            pk.clone_from_slice(input);
            Ok(PublicKey(pk))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid input length."
            ))
        }
    }
}

impl From<PublicKey> for Vec<u8> {
    fn from(PublicKey(pk): PublicKey) -> Vec<u8> {
        Vec::from(&pk[..])
    }
}

/// Newhope reconciliation data.
pub struct Reconciliation(pub [u8; SENDBBYTES]);

impl<'a> TryFrom<&'a [u8]> for Reconciliation {
    type Err = io::Error;
    fn try_from(input: &[u8]) -> io::Result<Self> {
        if input.len() == SENDBBYTES {
            let mut rec = [0; SENDBBYTES];
            rec.clone_from_slice(input);
            Ok(Reconciliation(rec))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid input length."
            ))
        }
    }
}

impl From<Reconciliation> for Vec<u8> {
    fn from(Reconciliation(rec): Reconciliation) -> Vec<u8> {
        Vec::from(&rec[..])
    }
}
