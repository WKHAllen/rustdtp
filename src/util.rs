use std::convert::TryFrom;

pub const LEN_SIZE: usize = 5;

pub fn dec_to_ascii(mut dec: usize) -> [u8; LEN_SIZE] {
	let mut ascii = [0u8; LEN_SIZE];
	for i in 0..LEN_SIZE {
		ascii[LEN_SIZE - i - 1] = u8::try_from(dec % 256).unwrap();
		dec >>= 8;
	}
	ascii
}

pub fn ascii_to_dec(ascii: [u8; LEN_SIZE]) -> usize {
	let mut dec: usize = 0;
	for i in 0..LEN_SIZE {
		dec <<= 8;
		dec += usize::from(ascii[i]);
	}
	dec
}
