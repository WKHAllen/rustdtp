#![crate_type = "lib"]
#![crate_name = "rustdtp"]

mod client;
mod server;
mod util;

pub use client::Client;
pub use server::Server;

#[cfg(test)]
mod tests {
	use super::*;
	use std::thread;
	use std::time::Duration;
	use util::*;

	const SLEEP_TIME: u64 = 100;

	macro_rules! sleep {
		($x:expr) => {
			thread::sleep(Duration::from_millis($x))
		};
		() => {
			thread::sleep(Duration::from_millis(SLEEP_TIME))
		};
	}

	fn server_on_receive(client_id: usize, message: &[u8]) {
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

	fn client_on_receive(message: &[u8]) {
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
		assert_eq!(decode_message_size(&[0, 0, 0, 0, 0]), 0);
		assert_eq!(decode_message_size(&[0, 0, 0, 0, 1]), 1);
		assert_eq!(decode_message_size(&[0, 0, 0, 0, 255]), 255);
		assert_eq!(decode_message_size(&[0, 0, 0, 1, 0]), 256);
		assert_eq!(decode_message_size(&[0, 0, 0, 1, 1]), 257);
		assert_eq!(decode_message_size(&[1, 1, 1, 1, 1]), 4311810305);
		assert_eq!(decode_message_size(&[1, 2, 3, 4, 5]), 4328719365);
		assert_eq!(decode_message_size(&[11, 7, 5, 3, 2]), 47362409218);
		assert_eq!(
			decode_message_size(&[255, 255, 255, 255, 255]),
			1099511627775
		);
	}

	#[test]
	fn test_server_builder() {
		let _server = Server::new()
			.on_receive(|_, _| {})
			.on_connect(|_| {})
			.on_disconnect(|_| {});
	}

	#[test]
	fn test_client_builder() {
		let _client = Client::new().on_receive(|_| {}).on_disconnected(|| {});
	}

	#[test]
	fn test_server() {
		let server = Server::new()
			.on_receive(server_on_receive)
			.on_connect(server_on_connect)
			.on_disconnect(server_on_disconnect)
			.start_default_host(0)
			.unwrap();

		sleep!();

		println!("Address: {}", server.get_addr().unwrap());

		assert!(server.serving().unwrap());
		sleep!();

		server.stop().unwrap();
		sleep!();

		assert!(!server.serving().unwrap());
	}

	#[test]
	fn test_drop() {
		{
			let server = Server::new()
				.on_receive(server_on_receive)
				.on_connect(server_on_connect)
				.on_disconnect(server_on_disconnect)
				.start_default_host(0)
				.unwrap();

			sleep!();

			let server_addr = server.get_addr().unwrap();
			println!("Server address: {}", server_addr);

			let client = Client::new()
				.on_receive(client_on_receive)
				.on_disconnected(client_on_disconnected)
				.connect_default_host(server_addr.port())
				.unwrap();

			sleep!();

			server.send_all("Hello, client #0.".as_bytes()).unwrap();
			sleep!();

			client.send("Hello, server.".as_bytes()).unwrap();
			sleep!();
		}

		sleep!();
	}

	#[test]
	fn test_main() {
		let server = Server::new()
			.on_receive(server_on_receive)
			.on_connect(server_on_connect)
			.on_disconnect(server_on_disconnect)
			.start_default_host(0)
			.unwrap();

		sleep!();

		let server_addr = server.get_addr().unwrap();
		println!("Server address: {}", server_addr);

		let client = Client::new()
			.on_receive(client_on_receive)
			.on_disconnected(client_on_disconnected)
			.connect_default_host(server_addr.port())
			.unwrap();

		sleep!();

		server.send_all("Hello, client #0.".as_bytes()).unwrap();
		sleep!();

		client.send("Hello, server.".as_bytes()).unwrap();
		sleep!();

		client.disconnect().unwrap();
		sleep!();

		server.stop().unwrap();
		sleep!();
	}
}
