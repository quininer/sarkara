use std::io;
use std::convert::TryFrom;
use seckey::Key;
use super::Signature;

use blissb::param::{ PRIVATEKEY_LENGTH, PUBLICKEY_LENGTH, SIGNATURE_LENGTH };


/// BLISS Signature Scheme.
///
/// # Example(signature)
/// ```
/// use sarkara::sign::{ Bliss, Signature };
///
/// let data = [9; 64];
/// let (sk, pk) = Bliss::keygen();
/// let sign = Bliss::signature(&sk, &data);
/// assert!(Bliss::verify(&pk, &sign, &data));
/// assert!(!Bliss::verify(&pk, &sign, &data[1..]));
/// ```
///
/// # Example(import/export)
/// ```
/// #![feature(try_from)]
/// # use std::convert::TryFrom;
/// # use sarkara::sign::{
/// #     Bliss, Signature,
/// #     PrivateKey, PublicKey, SignatureData
/// # };
/// #
/// # let data = [9; 64];
/// # let (sk, pk) = Bliss::keygen();
/// let sk_bytes: Vec<u8> = sk.into();
/// let pk_bytes: Vec<u8> = pk.into();
/// let sk = PrivateKey::try_from(&sk_bytes[..]).unwrap();
/// let pk = PublicKey::try_from(&pk_bytes[..]).unwrap();
/// # let sign = Bliss::signature(&sk, &data);
/// let sign_bytes: Vec<u8> = sign.into();
/// let sign = SignatureData::try_from(&sign_bytes[..]).unwrap();
/// # assert!(Bliss::verify(&pk, &sign, &data));
/// # assert!(!Bliss::verify(&pk, &sign, &data[1..]));
/// ```
pub struct Bliss;

impl Signature for Bliss {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Signature = SignatureData;

    #[inline] fn sk_length() -> usize { PRIVATEKEY_LENGTH }
    #[inline] fn pk_length() -> usize { PUBLICKEY_LENGTH }
    #[inline] fn sign_length() -> usize { SIGNATURE_LENGTH }

    fn keygen() -> (Self::PrivateKey, Self::PublicKey) {
        let sk = ::blissb::PrivateKey::new().unwrap();
        let pk = sk.public();
        (PrivateKey(sk.into()), PublicKey(pk))
    }

    fn signature(&PrivateKey(Key(ref sk)): &Self::PrivateKey, data: &[u8]) -> Self::Signature {
        SignatureData(sk.signature(data).unwrap())
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
            Ok(PrivateKey(
                ::blissb::PrivateKey::import(&sk)
                    .or(err!(InvalidInput, "PrivateKey: invalid input data."))?
                    .into()
            ))
        } else {
            err!(InvalidInput, "PrivateKey: invalid input length.")
        }
    },
    into: (input) -> Vec<u8> {
        let PrivateKey(Key(ref input)) = input;
        Vec::from(&input.export().unwrap()[..])
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
                    .or(err!(InvalidInput, "PublicKey: invalid input data."))?
            ))
        } else {
            err!(InvalidInput, "PublicKey: invalid input length.")
        }
    },
    into: (input) -> Vec<u8> {
        let PublicKey(ref input) = input;
        Vec::from(&input.export().unwrap()[..])
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
                    .or(err!(InvalidInput, "Signature: invalid input data."))?
            ))
        } else {
            err!(InvalidInput, "Signature: invalid input length.")
        }
    },
    into: (input) -> Vec<u8> {
        let SignatureData(ref input) = input;
        Vec::from(&input.export().unwrap()[..])
    }
);
