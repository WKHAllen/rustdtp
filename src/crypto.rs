use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

/// The number of bits to use for an RSA key.
pub const RSA_KEY_SIZE: usize = 2048;

/// The number of bytes to use for an AES key.
pub const AES_KEY_SIZE: usize = 32;

/// The number of bytes to use for an AES nonce.
pub const AES_NONCE_SIZE: usize = 12;

/// Generate a pair of RSA keys.
///
/// Returns a result containing the public and private keys, or the error variant if an error occurred while generating the keys.
pub fn rsa_keys() -> Result<(RsaPublicKey, RsaPrivateKey), rsa::errors::Error> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)?;
    let public_key = RsaPublicKey::from(&private_key);

    Ok((public_key, private_key))
}

/// Encrypt some data with RSA.
///
/// `public_key`: the RSA public key.
/// `plaintext`: the data to encrypt.
///
/// Returns a result containing the encrypted data, or the error variant if an error occurred while encrypting.
pub fn rsa_encrypt(
    public_key: &RsaPublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, rsa::errors::Error> {
    let mut rng = rand::thread_rng();
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let ciphertext = public_key.encrypt(&mut rng, padding, &plaintext[..])?;

    Ok(ciphertext)
}

/// Decrypt some data with RSA.
///
/// `private_key`: the RSA private key.
/// `ciphertext`: the data to decrypt.
///
/// Returns a result containing the decrypted data, or the error variant if an error occurred while decrypting.
pub fn rsa_decrypt(
    private_key: &RsaPrivateKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, rsa::errors::Error> {
    let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
    let plaintext = private_key.decrypt(padding, ciphertext)?;

    Ok(plaintext)
}

/// Generate an AES key.
///
/// Returns the AES key as an owned array.
pub fn aes_key() -> [u8; AES_KEY_SIZE] {
    rand::random()
}

/// Encrypt some data with AES.
///
/// `key`: the AES key.
/// `plaintext`: the data to encrypt.
///
/// Returns a result containing the encrypted data with the nonce prepended, or the error variant if an error occurred while encrypting.
pub fn aes_encrypt(key: &[u8; AES_KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let aes_key = Key::from(*key);
    let cipher = Aes256Gcm::new(&aes_key);
    let nonce_slice: [u8; AES_NONCE_SIZE] = rand::random();
    let nonce = Nonce::from(nonce_slice);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;

    let mut ciphertext_with_nonce = nonce_slice.to_vec();
    ciphertext_with_nonce.extend(ciphertext);

    Ok(ciphertext_with_nonce)
}

/// Decrypt some data with AES.
///
/// `key`: the AES key.
/// `ciphertext_with_nonce`: the data to decrypt, containing the prepended nonce.
///
/// Returns a result containing the decrypted data, or the error variant if an error occurred while decrypting.
pub fn aes_decrypt(
    key: &[u8; AES_KEY_SIZE],
    ciphertext_with_nonce: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let aes_key = Key::from(*key);
    let cipher = Aes256Gcm::new(&aes_key);
    let (nonce_slice, ciphertext) = ciphertext_with_nonce.split_at(AES_NONCE_SIZE);
    let nonce_slice_sized: [u8; AES_NONCE_SIZE] =
        nonce_slice.try_into().expect("incorrect nonce length");
    let nonce = Nonce::from(nonce_slice_sized);
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;

    Ok(plaintext)
}
