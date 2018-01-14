use rand::Rng;
use seckey::TempKey;
use ::kex::KeyExchange;
use ::aead::AeadCipher;


pub trait SealedBox: KeyExchange {
    fn send<R, AE>(r: R, pk: &Self::PublicKey)
        -> (Self::Message, AE)
        where
            R: Rng,
            AE: AeadCipher,
//            AE::KEY_LENGTH = Self::SHARED_LENGTH
    ;
    fn recv<AE>(sk: &Self::PrivateKey, m: &Self::Message)
        -> AE
        where
            AE: AeadCipher
    ;
}

impl<T> SealedBox for T where T: KeyExchange {
    fn send<R: Rng, AE: AeadCipher>(r: R, pk: &Self::PublicKey) -> (Self::Message, AE) {
        // TODO static assert
        assert_eq!(Self::SHARED_LENGTH, AE::KEY_LENGTH);
        let mut sharedkey = vec![0; Self::SHARED_LENGTH];
        let mut sharedkey = TempKey::from_slice(&mut sharedkey);

        let m = Self::exchange_to(r, &mut sharedkey, pk);
        let ae = AE::new(&sharedkey);

        (m, ae)
    }

    fn recv<AE: AeadCipher>(sk: &Self::PrivateKey, m: &Self::Message) -> AE {
        // TODO static assert
        assert_eq!(Self::SHARED_LENGTH, AE::KEY_LENGTH);
        let mut sharedkey = vec![0; Self::SHARED_LENGTH];
        let mut sharedkey = TempKey::from_slice(&mut sharedkey);

        Self::exchange_from(&mut sharedkey, sk, m);
        let ae = AE::new(&sharedkey);

        ae
    }
}
