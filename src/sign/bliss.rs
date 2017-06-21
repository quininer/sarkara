//! [bliss](http://bliss.di.ens.fr/).

use std::io;
use std::convert::TryFrom;
use rand::{ Rand, Rng };
use seckey::Key;
use super::Signature;

use blissb::param::{ PRIVATEKEY_LENGTH, PUBLICKEY_LENGTH, SIGNATURE_LENGTH };


/// BLISS Signature Scheme.
///
/// # Example(signature)
/// ```
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// use rand::ChaChaRng;
/// use sarkara::sign::{ Bliss, Signature };
///
/// let data = [9; 64];
/// let (sk, pk) = Bliss::keygen::<ChaChaRng>();
/// let sign = Bliss::signature::<ChaChaRng>(&sk, &data);
/// assert!(Bliss::verify(&pk, &sign, &data));
/// assert!(!Bliss::verify(&pk, &sign, &data[1..]));
/// # }
/// ```
///
/// # Example(import/export)
/// ```
/// #![feature(try_from)]
/// # extern crate rand;
/// # extern crate sarkara;
/// # fn main() {
/// # use std::convert::TryFrom;
/// # use rand::ChaChaRng;
/// # use sarkara::sign::{ Bliss, Signature };
/// #
/// # let data = [9; 64];
/// # let (sk, pk) = Bliss::keygen::<ChaChaRng>();
/// let sk_bytes: Vec<u8> = sk.into();
/// let pk_bytes: Vec<u8> = pk.into();
/// let sk = <Bliss as Signature>::PrivateKey::try_from(&sk_bytes[..]).unwrap();
/// let pk = <Bliss as Signature>::PublicKey::try_from(&pk_bytes[..]).unwrap();
/// # let sign = Bliss::signature::<ChaChaRng>(&sk, &data);
/// let sign_bytes: Vec<u8> = sign.into();
/// let sign = <Bliss as Signature>::Signature::try_from(&sign_bytes[..]).unwrap();
/// # assert!(Bliss::verify(&pk, &sign, &data));
/// # assert!(!Bliss::verify(&pk, &sign, &data[1..]));
/// # }
/// ```
pub struct Bliss;

impl Signature for Bliss {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Signature = SignatureData;

    const SK_LENGTH: usize = PRIVATEKEY_LENGTH;
    const PK_LENGTH: usize = PUBLICKEY_LENGTH;
    const SIGN_LENGTH: usize = SIGNATURE_LENGTH;

    fn keygen<R: Rand + Rng>() -> (Self::PrivateKey, Self::PublicKey) {
        let sk = ::blissb::PrivateKey::new::<R>().unwrap();
        let pk = sk.public();
        (PrivateKey(Key::from(sk)), PublicKey(pk))
    }

    fn signature<R: Rand + Rng>(&PrivateKey(ref sk): &Self::PrivateKey, data: &[u8]) -> Self::Signature {
        SignatureData(sk.signature::<R>(data).unwrap())
    }

    fn verify(
        &PublicKey(ref pk): &Self::PublicKey,
        &SignatureData(ref sign): &Self::Signature,
        data: &[u8]
    ) -> bool {
        pk.verify(sign, data)
    }
}


new_type!(
    /// BLISS private key.
    pub struct PrivateKey(pub Key<::blissb::PrivateKey>);
    from: (input) {
        if input.len() == PRIVATEKEY_LENGTH {
            let mut sk = [0; PRIVATEKEY_LENGTH];
            sk.clone_from_slice(input);
            Ok(PrivateKey(Key::from(
                ::blissb::PrivateKey::import(&sk)
                    .or_else(|_| err!(InvalidInput, "PrivateKey: invalid input data."))?
            )))
        } else {
            err!(InvalidInput, "PrivateKey: invalid input length.")
        }
    },
    into: (self) -> Vec<u8> {
        let PrivateKey(ref input) = self;
        Vec::from(&input.export().unwrap() as &[u8])
    }
);

new_type!(
    /// BLISS public key.
    pub struct PublicKey(pub ::blissb::PublicKey);
    from: (input) {
        if input.len() == PUBLICKEY_LENGTH {
            let mut pk = [0; PUBLICKEY_LENGTH];
            pk.clone_from_slice(input);
            Ok(PublicKey(
                ::blissb::PublicKey::import(&pk)
                    .or_else(|_| err!(InvalidInput, "PublicKey: invalid input data."))?
            ))
        } else {
            err!(InvalidInput, "PublicKey: invalid input length.")
        }
    },
    into: (self) -> Vec<u8> {
        let PublicKey(ref input) = self;
        Vec::from(&input.export().unwrap() as &[u8])
    }
);

new_type!(
    /// BLISS signature.
    pub struct SignatureData(pub ::blissb::Signature);
    from: (input) {
        if input.len() == SIGNATURE_LENGTH {
            let mut sign = [0; SIGNATURE_LENGTH];
            sign.clone_from_slice(input);
            Ok(SignatureData(
                ::blissb::Signature::import(&sign)
                    .or_else(|_| err!(InvalidInput, "Signature: invalid input data."))?
            ))
        } else {
            err!(InvalidInput, "Signature: invalid input length.")
        }
    },
    into: (self) -> Vec<u8> {
        let SignatureData(ref input) = self;
        Vec::from(&input.export().unwrap() as &[u8])
    }
);
