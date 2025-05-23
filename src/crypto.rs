//! Crypto utilities.

use crate::error::Result;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use rsa::sha2::Sha256;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use std::io;
use std::sync::Arc;

/// The number of bits to use for an RSA key.
pub const RSA_KEY_SIZE: usize = 2048;

/// The number of bytes to use for an AES key.
pub const AES_KEY_SIZE: usize = 32;

/// The number of bytes to use for an AES nonce.
pub const AES_NONCE_SIZE: usize = 12;

/// Generate a pair of RSA keys.
///
/// Returns a result containing the public and private keys, or the error
/// variant if an error occurred while generating the keys.
pub async fn rsa_keys() -> Result<(RsaPublicKey, RsaPrivateKey)> {
    tokio::task::spawn_blocking(move || {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok((public_key, private_key))
    })
    .await
    .unwrap()
}

/// Encrypt some data with RSA.
///
/// - `public_key`: the RSA public key.
/// - `plaintext`: the data to encrypt.
///
/// Returns a result containing the encrypted data, or the error variant if an
/// error occurred while encrypting.
pub async fn rsa_encrypt(public_key: RsaPublicKey, plaintext: Arc<[u8]>) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<Sha256>();
        let ciphertext = public_key.encrypt(&mut rng, padding, &plaintext[..])?;

        Ok(ciphertext)
    })
    .await
    .unwrap()
}

/// Decrypt some data with RSA.
///
/// - `private_key`: the RSA private key.
/// - `ciphertext`: the data to decrypt.
///
/// Returns a result containing the decrypted data, or the error variant if an
/// error occurred while decrypting.
pub async fn rsa_decrypt(private_key: RsaPrivateKey, ciphertext: Arc<[u8]>) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let padding = Oaep::new::<Sha256>();
        let plaintext = private_key.decrypt(padding, &ciphertext[..])?;

        Ok(plaintext)
    })
    .await
    .unwrap()
}

/// Generate an AES key.
///
/// Returns the AES key as an owned array.
pub async fn aes_key() -> [u8; AES_KEY_SIZE] {
    tokio::task::spawn_blocking(move || {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        key.as_slice().try_into().unwrap()
    })
    .await
    .unwrap()
}

/// Encrypt some data with AES.
///
/// - `key`: the AES key.
/// - `plaintext`: the data to encrypt.
///
/// Returns a result containing the encrypted data with the nonce prepended, or
/// the error variant if an error occurred while encrypting.
pub async fn aes_encrypt(key: [u8; AES_KEY_SIZE], plaintext: Arc<[u8]>) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;

        let mut ciphertext_with_nonce = nonce.to_vec();
        ciphertext_with_nonce.extend(ciphertext);

        Ok(ciphertext_with_nonce)
    })
    .await
    .unwrap()
}

/// Decrypt some data with AES.
///
/// - `key`: the AES key.
/// - `ciphertext_with_nonce`: the data to decrypt, containing the prepended
///   nonce.
///
/// Returns a result containing the decrypted data, or the error variant if an
/// error occurred while decrypting.
pub async fn aes_decrypt(
    key: [u8; AES_KEY_SIZE],
    ciphertext_with_nonce: Arc<[u8]>,
) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let (nonce_slice, ciphertext) = ciphertext_with_nonce.split_at(AES_NONCE_SIZE);
        let nonce_slice_sized: [u8; AES_NONCE_SIZE] = nonce_slice
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "incorrect nonce length"))?;

        let nonce = Nonce::from(nonce_slice_sized);
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;

        Ok(plaintext)
    })
    .await
    .unwrap()
}
