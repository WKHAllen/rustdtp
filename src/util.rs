use std::convert::TryFrom;

pub const LEN_SIZE: usize = 5;

pub const DEFAULT_SERVER_HOST: &str = "0.0.0.0";
pub const DEFAULT_CLIENT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 29275;

pub fn encode_message_size(mut size: usize) -> [u8; LEN_SIZE] {
	let mut encoded_size = [0u8; LEN_SIZE];

	for i in 0..LEN_SIZE {
		encoded_size[LEN_SIZE - i - 1] = u8::try_from(size % 256).unwrap();
		size >>= 8;
	}

	encoded_size
}

pub fn decode_message_size(encoded_size: &[u8; LEN_SIZE]) -> usize {
	let mut size: usize = 0;

	for i in 0..LEN_SIZE {
		size <<= 8;
		size += usize::from(encoded_size[i]);
	}

	size
}
