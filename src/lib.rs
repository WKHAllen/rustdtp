#![crate_type = "lib"]
#![crate_name = "rustdtp"]

mod client;
mod server;

pub use client::client::*;
pub use server::server::*;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn it_works() {
		assert_eq!(2 + 2, 4);
	}
}
