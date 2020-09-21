#![crate_type = "lib"]
#![crate_name = "rustdtp"]

mod client;
mod server;

pub use client::client::*;
pub use server::server::*;

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
}
