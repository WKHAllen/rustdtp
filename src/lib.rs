#![crate_type = "lib"]
#![crate_name = "rustdtp"]

mod client;
mod server;
mod util;

pub use client::client::*;
pub use server::server::*;
use util::*;

use std::time::Duration;
use std::thread;

#[cfg(test)]
mod tests {
	use super::*;

	fn server_on_recv(client_id: usize, message: &[u8]) {
		println!("Message from client #{}: {}", client_id, match std::str::from_utf8(message) {
			Ok(result) => result,
			Err(e) => panic!("Failed to parse message from client: {}", e),
		});
	}

	fn server_on_connect(client_id: usize) {
		println!("Client #{} connected", client_id);
	}

	fn server_on_disconnect(client_id: usize) {
		println!("Client #{} disconnected", client_id);
	}

	#[test]
	fn test_serve() {
		let mut server = Server::new(server_on_recv, server_on_connect, server_on_disconnect);
		server.start_default().unwrap();
		println!("Address: {}", server.get_addr().unwrap());
		server.stop().unwrap();
	}

	#[test]
	fn test_dec_to_ascii() {
		assert_eq!(dec_to_ascii(            0), [  0,   0,   0,   0,   0]);
		assert_eq!(dec_to_ascii(            1), [  0,   0,   0,   0,   1]);
		assert_eq!(dec_to_ascii(          255), [  0,   0,   0,   0, 255]);
		assert_eq!(dec_to_ascii(          256), [  0,   0,   0,   1,   0]);
		assert_eq!(dec_to_ascii(          257), [  0,   0,   0,   1,   1]);
		assert_eq!(dec_to_ascii(   4328719365), [  1,   2,   3,   4,   5]);
		assert_eq!(dec_to_ascii(  47362409218), [ 11,   7,   5,   3,   2]);
		assert_eq!(dec_to_ascii(1099511627775), [255, 255, 255, 255, 255]);
	}

	#[test]
	fn test_ascii_to_dec() {

	}
}
