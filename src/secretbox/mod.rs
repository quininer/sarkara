//! Secret-key Authentication encryption.

use ::aead::{ AeadCipher, DecryptFail };


/// `SecretBox` trait.
pub trait SecretBox: AeadCipher {
    /// Seal SecretBox.
    fn seal(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let (mut output, tag) = Self::new(key)
            .with_aad(nonce)
            .encrypt(nonce, data);
        output.extend_from_slice(&tag);
        output
    }

    /// Open SecretBox.
    fn open(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        if data.len() < Self::tag_length() { Err(DecryptFail::TagLengthError)? };

        let (data, tag) = data.split_at(data.len() - Self::tag_length());
        Self::new(key)
            .with_aad(nonce)
            .decrypt(nonce, data, tag)
    }
}

impl<T> SecretBox for T where T: AeadCipher {}
