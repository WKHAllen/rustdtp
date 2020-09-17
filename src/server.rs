pub mod server {
	use std::net::{TcpListener, TcpStream, Shutdown};

	enum ServerSock {
		Sock(TcpListener),
		Null,
	}

	enum ClientSock {
		Sock(TcpStream),
		Null,
	}

	pub struct Server {
		on_recv: fn(u32, &str),
		on_connect: fn(u32),
		on_disconnect: fn(u32),
		blocking: bool,
		event_blocking: bool,
		serving: bool,
		sock: ServerSock,
		clients: Vec<ClientSock>,
		next_client_id: usize,
		// TODO: add other attributes
	}

	impl Server {
		pub fn new(
			on_recv: fn(u32, &str),
			on_connect: fn(u32),
			on_disconnect: fn(u32),
			blocking: bool,
			event_blocking: bool
				) -> Server {
			Server {
				on_recv,
				on_connect,
				on_disconnect,
				blocking,
				event_blocking,
				serving: false,
				sock: ServerSock::Null,
				clients: Vec::new(),
				next_client_id: 0,
			}
		}

		pub fn new_default(
			on_recv: fn(u32, &str),
			on_connect: fn(u32),
			on_disconnect: fn(u32),
				) -> Server {
			Server::new(on_recv, on_connect, on_disconnect, false, false)
		}

		pub fn start(&mut self, host: &str, port: u16) -> std::io::Result<()> {
			if !self.serving {
				let addr = format!("{}:{}", host, port);
				let listener = TcpListener::bind(addr)?;
				self.sock = ServerSock::Sock(listener);

				self.serving = true;
				if self.blocking {
					// self.serve();
				} else {
					// TODO: spawn serve method in thread
				}
			}

			Ok(())
		}

		pub fn start_default_host(&mut self, port: u16) -> std::io::Result<()> {
			self.start("0.0.0.0", port)
		}

		pub fn start_default_port(&mut self, host: &str) -> std::io::Result<()> {
			self.start(host, 0)
		}

		pub fn start_default(&mut self) -> std::io::Result<()> {
			self.start("0.0.0.0", 0)
		}

		pub fn stop(&mut self) -> std::io::Result<()> {
			if self.serving {
				self.serving = false;

				for client in &self.clients {
					match client {
						ClientSock::Sock(stream) => stream.shutdown(Shutdown::Both),
						ClientSock::Null => Ok(()),
					}?;
				}

				// TODO: shut down listener
			}

			Ok(())
		}

		// TODO: complete implementation
	}
}
