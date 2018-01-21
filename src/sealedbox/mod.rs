use rand::Rng;
use seckey::TempKey;
use ::kex::KeyExchange;
use ::aead::{ AeadCipher, Online };


pub struct Sealing<AE: AeadCipher>(AE);
pub struct Opening<AE: AeadCipher>(AE);

pub trait SealedBox: KeyExchange {
    fn send<R, AE>(r: R, pk: &Self::PublicKey)
        -> (Self::Message, Sealing<AE>)
        where
            R: Rng,
            AE: AeadCipher,
//            AE::KEY_LENGTH = Self::SHARED_LENGTH
    ;
    fn recv<AE>(sk: &Self::PrivateKey, m: &Self::Message)
        -> Opening<AE>
        where AE: AeadCipher;
}

impl<T> SealedBox for T where T: KeyExchange {
    fn send<R: Rng, AE: AeadCipher>(r: R, pk: &Self::PublicKey) -> (Self::Message, Sealing<AE>) {
        // TODO static assert
        assert_eq!(Self::SHARED_LENGTH, AE::KEY_LENGTH);
        let mut sharedkey = vec![0; Self::SHARED_LENGTH];
        let mut sharedkey = TempKey::from_slice(&mut sharedkey);

        let m = Self::exchange_to(r, &mut sharedkey, pk);
        let ae = AE::new(&sharedkey);

        (m, Sealing(ae))
    }

    fn recv<AE: AeadCipher>(sk: &Self::PrivateKey, m: &Self::Message) -> Opening<AE> {
        // TODO static assert
        assert_eq!(Self::SHARED_LENGTH, AE::KEY_LENGTH);
        let mut sharedkey = vec![0; Self::SHARED_LENGTH];
        let mut sharedkey = TempKey::from_slice(&mut sharedkey);

        Self::exchange_from(&mut sharedkey, sk, m);
        let ae = AE::new(&sharedkey);

        Opening(ae)
    }
}

impl<AE: AeadCipher> Sealing<AE> {
    #[inline]
    pub fn seal(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), AE::Error> {
        self.0.seal(nonce, aad, input, output)
    }
}

impl<'a, AE: AeadCipher + Online<'a>> Sealing<AE> {
    #[inline]
    pub fn encrypt(&'a self, nonce: &[u8], aad: &[u8]) -> AE::Encryption {
        self.0.encrypt(nonce, aad)
    }
}

impl<AE: AeadCipher> Opening<AE> {
    #[inline]
    pub fn open(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<bool, AE::Error> {
        self.0.open(nonce, aad, input, output)
    }
}

impl<'a, AE: AeadCipher + Online<'a>> Opening<AE> {
    #[inline]
    pub fn decrypt(&'a self, nonce: &[u8], aad: &[u8]) -> AE::Decryption {
        self.0.decrypt(nonce, aad)
    }
}
