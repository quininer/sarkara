//! Secret-key Authentication encryption.

use ::aead::{ AeadCipher, DecryptFail };


/// `SecretBox` trait.
pub trait SecretBox: AeadCipher {
    /// Seal SecretBox.
    fn seal(key: &[u8], data: &[u8]) -> Vec<u8> {
        let nonce = rand!(Self::nonce_length());
        let output = Self::new(key)
            .with_aad(&nonce)
            .encrypt(&nonce, data);

        [nonce, output].concat()
    }

    /// Open SecretBox.
    fn open(key: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        if data.len() < Self::tag_length() { Err(DecryptFail::TagLengthError)? };

        let (nonce, data) = data.split_at(Self::nonce_length());
        Self::new(key)
            .with_aad(nonce)
            .decrypt(nonce, data)
    }
}

impl<T> SecretBox for T where T: AeadCipher {}
