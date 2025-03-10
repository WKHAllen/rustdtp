//! Crate-level utilities.

use std::convert::TryFrom;

/// The length of the size portion of each message sent through a socket.
pub const LEN_SIZE: usize = 5;

/// The size of a channel buffer.
pub const CHANNEL_BUFFER_SIZE: usize = 256;

/// The maximum time in milliseconds to wait for data from a socket.
pub const DATA_READ_TIMEOUT: u64 = 1000;

/// The maximum time in milliseconds to wait for an initial handshake.
pub const HANDSHAKE_TIMEOUT: u64 = 60000;

/// Encode the size portion of a message.
///
/// - `size`: the message size.
///
/// Returns the message size encoded in bytes.
pub fn encode_message_size(size: usize) -> [u8; LEN_SIZE] {
    (0..LEN_SIZE)
        .fold((size, [0u8; LEN_SIZE]), |(size, mut encoded_size), i| {
            encoded_size[LEN_SIZE - i - 1] = u8::try_from(size & 0xff).unwrap();
            (size >> 8, encoded_size)
        })
        .1
}

/// Decode the size portion of a message.
///
/// - `encoded_size`: the message size encoded in bytes.
///
/// Returns the size of the message.
#[allow(clippy::trivially_copy_pass_by_ref)]
pub fn decode_message_size(encoded_size: &[u8; LEN_SIZE]) -> usize {
    encoded_size
        .iter()
        .fold(0, |acc, x| (acc << 8) + usize::from(*x))
}

/// Assert that an enum is of the given variant, and unwrap the value within the
/// variant.
macro_rules! unwrap_enum {
    ($enum:expr, $variant:path) => {{
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

/// Break from a block if a `Result` is an `Err`. Essentially the equivalent of
/// the `?` operator but for blocks instead of functions.
macro_rules! break_on_err {
    ($x:expr) => {
        match $x {
            Ok(v) => v,
            Err(e) => {
                break Err(e.into());
            },
        }
    };
    ($x:expr, $label:lifetime) => {
        match $x {
            Ok(v) => v,
            Err(e) => {
                break $label Err(e.into());
            },
        }
    };
}

pub(crate) use break_on_err;
pub(crate) use unwrap_enum;
