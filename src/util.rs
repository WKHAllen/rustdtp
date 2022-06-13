//! Utilities for the crate.

use std::convert::TryFrom;
use std::error;
use std::io;

/// The length of the size portion of each message sent through a socket.
pub const LEN_SIZE: usize = 5;

/// The size of a channel buffer.
pub const CHANNEL_BUFFER_SIZE: usize = 100;

/// A crate-specific error.
pub enum Error {
    InvalidClientID,
    ChannelWrongResponse,
}

impl Error {
    pub fn message(&self) -> &str {
        match self {
            Self::InvalidClientID => "Invalid client ID",
            Self::ChannelWrongResponse => "Incorrect return value from command channel",
        }
    }
}

/// Generate a generic IO error.
///
/// `err`: the underlying error.
///
/// Returns a generic IO representation of the error.
pub fn generic_io_error<T, E>(err: E) -> io::Result<T>
where
    E: Into<Box<dyn error::Error + Send + Sync>>,
{
    Err(io::Error::new(io::ErrorKind::Other, err))
}

/// Encode the size portion of a message.
///
/// `size`: the message size.
///
/// Returns the message size encoded in bytes.
pub fn encode_message_size(mut size: usize) -> [u8; LEN_SIZE] {
    let mut encoded_size = [0u8; LEN_SIZE];

    for i in 0..LEN_SIZE {
        encoded_size[LEN_SIZE - i - 1] = u8::try_from(size % 256).unwrap();
        size >>= 8;
    }

    encoded_size
}

/// Decode the size portion of a message.
///
/// `encoded_size`: the message size encoded in bytes.
///
/// Returns the size of the message.
pub fn decode_message_size(encoded_size: &[u8; LEN_SIZE]) -> usize {
    let mut size: usize = 0;

    for i in 0..LEN_SIZE {
        size <<= 8;
        size += usize::from(encoded_size[i]);
    }

    size
}
