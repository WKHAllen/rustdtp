//! Utilities for the crate.

use std::convert::TryFrom;
use std::error;
use std::io;
use std::ops::Deref;

/// The length of the size portion of each message sent through a socket.
pub const LEN_SIZE: usize = 5;

/// The default host address for a server to serve on.
pub const DEFAULT_SERVER_HOST: &str = "0.0.0.0";

/// The default host address for a client to connect to.
pub const DEFAULT_CLIENT_HOST: &str = "127.0.0.1";

/// The default port for a server to serve on or a client to connect to.
pub const DEFAULT_PORT: u16 = 29275;

/// A crate-specific error.
pub enum Error {
    NotServing,
    AlreadyServing,
    ServerClosed,
    NotConnected,
    AlreadyConnected,
    ClientDisconnected,
    InvalidClientID,
    ChannelWrongResponse,
}

impl Deref for Error {
    type Target = &'static str;

    /// Dereference a crate-specific error to get the string representation of the error.
    /// 
    /// Returns the string representation of the error.
    fn deref(&self) -> &Self::Target {
        match self {
            Self::NotServing => &"Not serving clients",
            Self::AlreadyServing => &"Already serving clients",
            Self::ServerClosed => &"Server closed",
            Self::NotConnected => &"Not connected to a server",
            Self::AlreadyConnected => &"Already connected to a server",
            Self::ClientDisconnected => &"Client disconnected",
            Self::InvalidClientID => &"Invalid client ID",
            Self::ChannelWrongResponse => &"Incorrect return value from command channel",
        }
    }
}

/// Generate a generic IO error.
/// 
/// `err`: the underlying error.
/// 
/// Returns a generic IO representation of the error.
pub fn generic_error<T, E>(err: E) -> io::Result<T>
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
