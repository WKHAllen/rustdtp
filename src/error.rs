//! Crate-level error types.

use std::io;
use thiserror::Error;

/// All possible DTP error types.
#[derive(Error, Debug)]
pub enum Error {
    /// An I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    /// A JSON error.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    /// An RSA error.
    #[error("RSA error: {0}")]
    RsaError(#[from] rsa::Error),
    /// An invalid RSA key encoding error.
    #[error("invalid RSA key encoding")]
    InvalidRsaKeyEncoding,
    /// An AES error.
    #[error("AES error: {0}")]
    AesError(#[from] aes_gcm::Error),
    /// An invalid AES key size error.
    #[error("invalid AES key size")]
    InvalidAesKeySize,
    /// A network operation was attempted, but the connection was closed.
    #[error("the connection has been closed")]
    ConnectionClosed,
    /// An operation was attempted involving a client, but the provided client
    /// ID was invalid.
    #[error("invalid client ID: {0}")]
    InvalidClientId(usize),
}

/// DTP `Result` type alias.
pub type Result<T> = core::result::Result<T, Error>;
