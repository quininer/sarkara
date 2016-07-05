use ::auth::Tag;
use ::utils::Bytes;
use super::{ AeadCipher, DecryptFail };


/// Norx.
///
/// # Example(encrypt/decrypt)
/// ```
/// use sarkara::utils::Bytes;
/// use sarkara::aead::{ Norx, AeadCipher };
///
/// let (pass, nonce) = (
///     Bytes::random(Norx::key_length()),
///     Bytes::random(Norx::nonce_length())
/// );
/// let Bytes(ref data) = Bytes::random(64);
/// let (ciphertext, tag) = Norx::new(&pass)
///     .with_aad(&nonce)
///     .encrypt(&nonce, &data);
/// let plaintext = Norx::new(&pass)
///     .with_aad(&nonce)
///     .decrypt(&nonce, &ciphertext, &tag)
///     .unwrap();
/// assert_eq!(plaintext, &data[..]);
/// ```
#[derive(Clone, Debug)]
pub struct Norx {
    /// key.
    pub key: Bytes,
    /// associated data.
    pub aad: Vec<u8>
}

impl AeadCipher for Norx {
    fn new(key: &[u8]) -> Self {
        Norx {
            key: Bytes::new(key),
            aad: Vec::new()
        }
    }

    fn with_aad(&mut self, aad: &[u8]) -> &mut Self {
        self.aad = aad.into();
        self
    }

    fn key_length() -> usize { 32 }
    fn tag_length() -> usize { 32 }
    fn nonce_length() -> usize { 16 }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> (Vec<u8>, Tag) {
        let output = ::norx::norx6441::encrypt(&self.aad, data, &[], nonce, &self.key);
        let (output, tag) = output.split_at(data.len());
        (output.into(), Bytes::new(tag))
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8], tag: &[u8]) -> Result<Vec<u8>, DecryptFail> {
        if tag.len() != Self::tag_length() { Err(DecryptFail::TagLengthError)? };

        let input = [data, tag].concat();
        ::norx::norx6441::decrypt(&self.aad, &input, &[], nonce, &self.key)
            .ok_or(DecryptFail::AuthenticationFail)
    }
}
