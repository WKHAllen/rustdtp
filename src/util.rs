use std::convert::TryFrom;
use std::error;
use std::io;

/// The length of the size portion of each message sent through a socket.
pub const LEN_SIZE: usize = 5;

/// The size of a channel buffer.
pub const CHANNEL_BUFFER_SIZE: usize = 256;

/// The maximum time in milliseconds to wait for data from a socket.
pub const DATA_READ_TIMEOUT: u64 = 1000;

/// The maximum time in milliseconds to wait for an initial handshake.
pub const HANDSHAKE_TIMEOUT: u64 = 60000;

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

/// Convert a result into a generic IO result.
///
/// `value`: the result to convert.
///
/// Returns the result converted into a generic IO result.
pub fn into_generic_io_result<T, E>(value: Result<T, E>) -> io::Result<T>
where
    E: Into<Box<dyn error::Error + Send + Sync>>,
{
    match value {
        Ok(val) => Ok(val),
        Err(e) => generic_io_error(e),
    }
}

/// Encode the size portion of a message.
///
/// `size`: the message size.
///
/// Returns the message size encoded in bytes.
pub fn encode_message_size(mut size: usize) -> [u8; LEN_SIZE] {
    let mut encoded_size = [0u8; LEN_SIZE];

    for i in 0..LEN_SIZE {
        encoded_size[LEN_SIZE - i - 1] = u8::try_from(size & 0xff).unwrap();
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

/// Assert that an enum is of the given variant, and unwrap the value within the variant.
macro_rules! unwrap_enum {
    ($enum: expr, $variant: path) => {{
        if let $variant(x) = $enum {
            x
        } else {
            panic!(
                "mismatch variant when unwrapping enum {}",
                stringify!($variant)
            );
        }
    }};
}

pub(crate) use unwrap_enum;
