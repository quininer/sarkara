use ::aead::{ AeadCipher, DecryptFail };
use ::kex::KeyExchange;


pub trait SealedBox<K>: AeadCipher where K: KeyExchange {
    fn seal(pka: &[u8], data: &[u8]) -> Vec<u8>;
    fn open(ska: &K::PrivateKey, data: &[u8]) -> Result<Vec<u8>, DecryptFail>;
}

impl<T, K> SealedBox<K> for T where
    T: AeadCipher,
    K: KeyExchange
{
    fn seal(pka: &[u8], data: &[u8]) -> Vec<u8> {
        let mut input = vec![0; Self::key_length() + Self::nonce_length()];
        let rec = K::exchange(&mut input, pka);

        let mut output = Self::new(&input[..Self::key_length()])
            .with_aad(&rec)
            .encrypt(&input[Self::key_length()..], data);
        output.extend_from_slice(&rec);
        output
    }

    fn open(ska: &K::PrivateKey, data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        let mut input = vec![0; Self::key_length() + Self::nonce_length()];
        let (data, rec) = data.split_at(data.len() - K::rec_length());
        K::exchange_from(&mut input, ska, rec);

        Self::new(&input[..Self::key_length()])
            .with_aad(rec)
            .decrypt(&input[Self::key_length()..], data)
    }
}
