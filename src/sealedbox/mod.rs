use std::marker::PhantomData;
use rand::{ Rng, CryptoRng };
use seckey::TempKey;
use ::kex::{ KeyExchange, CheckedExchange };
use ::aead::{ AeadCipher, Online };
use ::Error;


pub struct SealedBox<KEX, AE>(PhantomData<(KEX, AE)>);
pub struct Sealing<AE: AeadCipher>(AE);
pub struct Opening<AE: AeadCipher>(AE);


impl<KEX, AE> SealedBox<KEX, AE>
    where
        KEX: KeyExchange,
        AE: AeadCipher,
//        AE::KEY_LENGTH = KEX::SHARED_LENGTH
{
    pub fn send<R: Rng + CryptoRng>(r: R, pk: &KEX::PublicKey) -> (KEX::Message, Sealing<AE>) {
        // TODO static assert
        assert_eq!(KEX::SHARED_LENGTH, AE::KEY_LENGTH);
        let mut sharedkey: Vec<u8> = vec![0; KEX::SHARED_LENGTH];
        let mut sharedkey = TempKey::from(&mut sharedkey as &mut [u8]);

        let m = KEX::exchange_to(r, &mut sharedkey, pk);
        let ae = AE::new(&sharedkey);

        (m, Sealing(ae))
    }

    pub fn recv(sk: &KEX::PrivateKey, m: &KEX::Message) -> Opening<AE> {
        // TODO static assert
        assert_eq!(KEX::SHARED_LENGTH, AE::KEY_LENGTH);
        let mut sharedkey: Vec<u8> = vec![0; KEX::SHARED_LENGTH];
        let mut sharedkey = TempKey::from(&mut sharedkey as &mut [u8]);

        KEX::exchange_from(&mut sharedkey, sk, m);
        let ae = AE::new(&sharedkey);

        Opening(ae)
    }
}

impl<KEX, AE> SealedBox<KEX, AE>
    where
        KEX: CheckedExchange,
        AE: AeadCipher
{
    pub fn checked_recv(sk: &KEX::PrivateKey, m: &KEX::Message) -> Result<Opening<AE>, Error> {
        // TODO static assert
        assert_eq!(KEX::SHARED_LENGTH, AE::KEY_LENGTH);
        let mut sharedkey: Vec<u8> = vec![0; KEX::SHARED_LENGTH];
        let mut sharedkey = TempKey::from(&mut sharedkey as &mut [u8]);

        <KEX as CheckedExchange>::exchange_from(&mut sharedkey, sk, m)?;
        let ae = AE::new(&sharedkey);

        Ok(Opening(ae))
    }
}

impl<AE: AeadCipher> Sealing<AE> {
    #[inline]
    pub fn seal(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Error> {
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
    pub fn open(&self, nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        self.0.open(nonce, aad, input, output)
    }
}

impl<'a, AE: AeadCipher + Online<'a>> Opening<AE> {
    #[inline]
    pub fn decrypt(&'a self, nonce: &[u8], aad: &[u8]) -> AE::Decryption {
        self.0.decrypt(nonce, aad)
    }
}
