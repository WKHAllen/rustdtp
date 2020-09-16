pub mod server {
	use std::net::{TcpListener, TcpStream};

	enum ServerSock {
		Sock(TcpListener),
		Null,
	}

	pub struct Server<'a> {
		max_clients: u32,
		on_recv: fn(u32, &str),
		on_connect: fn(u32),
		on_disconnect: fn(u32),
		blocking: bool,
		event_blocking: bool,
		serving: bool,
		sock: ServerSock,
		clients: &'a[TcpStream],
		allocated_clients: &'a[bool],
		next_client_id: u32,
		// TODO: add other attributes
	}

	impl Server<'_> {
		pub fn new(
			max_clients: u32,
			on_recv: fn(u32, &str),
			on_connect: fn(u32),
			on_disconnect: fn(u32),
			blocking: bool,
			event_blocking: bool
				) -> Server<'static> {
			Server {
				max_clients,
				on_recv,
				on_connect,
				on_disconnect,
				blocking,
				event_blocking,
				serving: false,
				sock: ServerSock::Null,
				clients: &[],
				allocated_clients: &[],
				next_client_id: 0,
			}
		}

		// TODO: complete implementation
	}
}
