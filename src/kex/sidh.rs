use rand::Rng;
use seckey::{ SecKey, zero };
use sidh::sidh;
use super::KeyExchange;
use ::Packing;


pub struct Sidh;
pub struct PrivateKey(SecKey<sidh::SIDHSecretKeyAlice>);
pub struct PublicKey(sidh::SIDHPublicKeyAlice);
pub struct Message(sidh::SIDHPublicKeyBob);

impl KeyExchange for Sidh {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Message = Message;

    const SHARED_LENGTH: usize = sidh::SHARED_SECRET_SIZE;

    fn keypair<R: Rng>(mut r: R) -> (Self::PrivateKey, Self::PublicKey) {
        let (pk, sk) = sidh::generate_alice_keypair(&mut r);
        (PrivateKey(SecKey::new(sk).ok().expect("memsec malloc failed")), PublicKey(pk))
    }

    fn exchange_to<R: Rng>(mut r: R, sharedkey: &mut [u8], &PublicKey(ref pka): &Self::PublicKey) -> Self::Message {
        let (pkb, skb) = sidh::generate_bob_keypair(&mut r);

        let mut key = skb.shared_secret(pka);
        sharedkey.copy_from_slice(&key);
        zero(&mut key);

        Message(pkb)
    }

    fn exchange_from(sharedkey: &mut [u8], &PrivateKey(ref ska): &Self::PrivateKey, &Message(ref pkb): &Self::Message) {
        let mut key = ska.read().shared_secret(pkb);
        sharedkey.copy_from_slice(&key);
        zero(&mut key);
    }
}


impl Packing for PrivateKey {
    const BYTES_LENGTH: usize = sidh::SECRET_KEY_SIZE;

    fn read_bytes(&self, buf: &mut [u8]) {
        let buf = array_mut_ref!(buf, 0, sidh::SECRET_KEY_SIZE);
        buf.clone_from(&self.0.read().scalar)
    }

    fn from_bytes(buf: &[u8]) -> Self {
        let buf = array_ref!(buf, 0, sidh::SECRET_KEY_SIZE);
        let sk = sidh::SIDHSecretKeyAlice { scalar: buf.clone() };
        SecKey::new(sk)
            .map(PrivateKey)
            .expect("memsec malloc failed")
    }
}

impl Packing for PublicKey {
    const BYTES_LENGTH: usize = sidh::PUBLIC_KEY_SIZE;

    fn read_bytes(&self, buf: &mut [u8]) {
        let buf = array_mut_ref!(buf, 0, sidh::PUBLIC_KEY_SIZE);
        buf.clone_from(&self.0.to_bytes())
    }

    fn from_bytes(buf: &[u8]) -> Self {
        assert_eq!(buf.len(), sidh::PUBLIC_KEY_SIZE);
        PublicKey(sidh::SIDHPublicKeyAlice::from_bytes(buf))
    }
}

impl Packing for Message {
    const BYTES_LENGTH: usize = sidh::PUBLIC_KEY_SIZE;

    fn read_bytes(&self, buf: &mut [u8]) {
        let buf = array_mut_ref!(buf, 0, sidh::PUBLIC_KEY_SIZE);
        buf.clone_from(&self.0.to_bytes())
    }

    fn from_bytes(buf: &[u8]) -> Self {
        assert_eq!(buf.len(), sidh::PUBLIC_KEY_SIZE);
        Message(sidh::SIDHPublicKeyBob::from_bytes(buf))
    }
}
