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

	fn server_on_recv(client_id: usize, message: &[u8], _: &()) {
		println!(
			"Message from client #{}: {}",
			client_id,
			match std::str::from_utf8(message) {
				Ok(result) => result,
				Err(e) => panic!("Failed to parse message from client: {}", e),
			}
		);
	}

	fn server_on_connect(client_id: usize, _: &()) {
		println!("Client #{} connected", client_id);
	}

	fn server_on_disconnect(client_id: usize, _: &()) {
		println!("Client #{} disconnected", client_id);
	}

	fn client_on_recv(message: &[u8], _: &()) {
		println!(
			"Message from server: {}",
			match std::str::from_utf8(message) {
				Ok(result) => result,
				Err(e) => panic!("Failed to parse message from server: {}", e),
			}
		);
	}

	fn client_on_disconnected(_: &()) {
		println!("Disconnected from server");
	}

	#[test]
	fn test_dec_to_ascii() {
		assert_eq!(dec_to_ascii(0), [0, 0, 0, 0, 0]);
		assert_eq!(dec_to_ascii(1), [0, 0, 0, 0, 1]);
		assert_eq!(dec_to_ascii(255), [0, 0, 0, 0, 255]);
		assert_eq!(dec_to_ascii(256), [0, 0, 0, 1, 0]);
		assert_eq!(dec_to_ascii(257), [0, 0, 0, 1, 1]);
		assert_eq!(dec_to_ascii(4311810305), [1, 1, 1, 1, 1]);
		assert_eq!(dec_to_ascii(4328719365), [1, 2, 3, 4, 5]);
		assert_eq!(dec_to_ascii(47362409218), [11, 7, 5, 3, 2]);
		assert_eq!(dec_to_ascii(1099511627775), [255, 255, 255, 255, 255]);
	}

	#[test]
	fn test_ascii_to_dec() {
		assert_eq!(ascii_to_dec([0, 0, 0, 0, 0]), 0);
		assert_eq!(ascii_to_dec([0, 0, 0, 0, 1]), 1);
		assert_eq!(ascii_to_dec([0, 0, 0, 0, 255]), 255);
		assert_eq!(ascii_to_dec([0, 0, 0, 1, 0]), 256);
		assert_eq!(ascii_to_dec([0, 0, 0, 1, 1]), 257);
		assert_eq!(ascii_to_dec([1, 1, 1, 1, 1]), 4311810305);
		assert_eq!(ascii_to_dec([1, 2, 3, 4, 5]), 4328719365);
		assert_eq!(ascii_to_dec([11, 7, 5, 3, 2]), 47362409218);
		assert_eq!(ascii_to_dec([255, 255, 255, 255, 255]), 1099511627775);
	}

	#[test]
	fn test_serve() {
		let mut server = Server::new(
			server_on_recv,
			server_on_connect,
			server_on_disconnect,
			&(),
			&(),
			&(),
		);
		server.start_default_host(TEST_PORT).unwrap();
		println!("Address: {}", server.get_addr().unwrap());
		server.stop().unwrap();
	}

	#[test]
	fn test_all() {
		let mut server = Server::new(
			server_on_recv,
			server_on_connect,
			server_on_disconnect,
			&(),
			&(),
			&(),
		);
		let server_thread = std::thread::spawn(move || {
			server.start_default_host(TEST_PORT).unwrap();
			thread::sleep(Duration::from_millis(2 * SLEEP_TIME));

			server.send_all("Hello, client #0.".as_bytes()).unwrap();
			thread::sleep(Duration::from_millis(3 * SLEEP_TIME));

			server.stop().unwrap();
		});

		thread::sleep(Duration::from_millis(SLEEP_TIME));

		let client_thread = std::thread::spawn(move || {
			let mut client = Client::new(client_on_recv, client_on_disconnected, &(), &());
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
