#![crate_type = "lib"]
#![crate_name = "rustdtp"]

mod client;
mod server;
mod util;

pub use client::client::*;
pub use server::server::*;

#[cfg(test)]
mod tests {
	use super::*;
	use std::thread;
	use std::time::Duration;
	use util::*;

	const TEST_PORT: u16 = 29275;
	const SLEEP_TIME: u64 = 100;

	fn server_on_recv(client_id: usize, message: &[u8]) {
		println!(
			"Message from client #{}: {}",
			client_id,
			match std::str::from_utf8(message) {
				Ok(result) => result,
				Err(e) => panic!("Failed to parse message from client: {}", e),
			}
		);
	}

	fn server_on_connect(client_id: usize) {
		println!("Client #{} connected", client_id);
	}

	fn server_on_disconnect(client_id: usize) {
		println!("Client #{} disconnected", client_id);
	}

	fn client_on_recv(message: &[u8]) {
		println!(
			"Message from server: {}",
			match std::str::from_utf8(message) {
				Ok(result) => result,
				Err(e) => panic!("Failed to parse message from server: {}", e),
			}
		);
	}

	fn client_on_disconnected() {
		println!("Disconnected from server");
	}

	#[test]
	fn test_encode_message_size() {
		assert_eq!(encode_message_size(0), [0, 0, 0, 0, 0]);
		assert_eq!(encode_message_size(1), [0, 0, 0, 0, 1]);
		assert_eq!(encode_message_size(255), [0, 0, 0, 0, 255]);
		assert_eq!(encode_message_size(256), [0, 0, 0, 1, 0]);
		assert_eq!(encode_message_size(257), [0, 0, 0, 1, 1]);
		assert_eq!(encode_message_size(4311810305), [1, 1, 1, 1, 1]);
		assert_eq!(encode_message_size(4328719365), [1, 2, 3, 4, 5]);
		assert_eq!(encode_message_size(47362409218), [11, 7, 5, 3, 2]);
		assert_eq!(
			encode_message_size(1099511627775),
			[255, 255, 255, 255, 255]
		);
	}

	#[test]
	fn test_decode_message_size() {
		assert_eq!(decode_message_size([0, 0, 0, 0, 0]), 0);
		assert_eq!(decode_message_size([0, 0, 0, 0, 1]), 1);
		assert_eq!(decode_message_size([0, 0, 0, 0, 255]), 255);
		assert_eq!(decode_message_size([0, 0, 0, 1, 0]), 256);
		assert_eq!(decode_message_size([0, 0, 0, 1, 1]), 257);
		assert_eq!(decode_message_size([1, 1, 1, 1, 1]), 4311810305);
		assert_eq!(decode_message_size([1, 2, 3, 4, 5]), 4328719365);
		assert_eq!(decode_message_size([11, 7, 5, 3, 2]), 47362409218);
		assert_eq!(
			decode_message_size([255, 255, 255, 255, 255]),
			1099511627775
		);
	}

	#[test]
	fn test_serve() {
		let mut server = Server::new(
			Box::new(server_on_recv),
			Box::new(server_on_connect),
			Box::new(server_on_disconnect),
		);
		server.start_default_host(TEST_PORT).unwrap();
		println!("Address: {}", server.get_addr().unwrap());
		server.stop().unwrap();
	}

	#[test]
	fn test_all() {
		let mut server = Server::new(server_on_recv, server_on_connect, server_on_disconnect);
		let server_thread = std::thread::spawn(move || {
			server.start_default_host(TEST_PORT).unwrap();
			thread::sleep(Duration::from_millis(2 * SLEEP_TIME));

			server.send_all("Hello, client #0.".as_bytes()).unwrap();
			thread::sleep(Duration::from_millis(3 * SLEEP_TIME));

			server.stop().unwrap();
		});

		thread::sleep(Duration::from_millis(SLEEP_TIME));

		let client_thread = std::thread::spawn(move || {
			let mut client = Client::new(client_on_recv, client_on_disconnected);
			client.connect_default_host(TEST_PORT).unwrap();
			thread::sleep(Duration::from_millis(2 * SLEEP_TIME));

			client.send("Hello, server.".as_bytes()).unwrap();
			thread::sleep(Duration::from_millis(SLEEP_TIME));

			client.disconnect().unwrap();
		});

		client_thread.join().unwrap();
		server_thread.join().unwrap();
	}
}
