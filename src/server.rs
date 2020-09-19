pub mod server {
	use std::net::{TcpListener, TcpStream, Shutdown, SocketAddr};
	use std::thread;
	use std::collections::HashMap;
	use std::io;
	use std::time::Duration;

	enum ServerSock {
		Sock(TcpListener),
		Null,
	}

	enum ClientSock {
		Sock(TcpStream),
		Null,
	}

	pub struct Server {
		on_recv: fn(usize, &str),
		on_connect: fn(usize),
		on_disconnect: fn(usize),
		blocking: bool,
		event_blocking: bool,
		serving: bool,
		sock: ServerSock,
		clients: HashMap<usize, ClientSock>,
		// TODO: add other attributes
	}

	impl Server {
		pub fn new(
			on_recv: fn(usize, &str),
			on_connect: fn(usize),
			on_disconnect: fn(usize),
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
				clients: HashMap::new(),
			}
		}

		pub fn new_default(
			on_recv: fn(usize, &str),
			on_connect: fn(usize),
			on_disconnect: fn(usize),
				) -> Server {
			Server::new(on_recv, on_connect, on_disconnect, false, false)
		}

		pub fn start(&mut self, host: &str, port: u16) -> io::Result<()> {
			if !self.serving {
				let addr = format!("{}:{}", host, port);
				let listener = TcpListener::bind(addr)?;
				self.sock = ServerSock::Sock(listener);

				self.serving = true;
				if self.blocking {
					self.serve()?;
				} else {
					// TODO: spawn serve method in thread
				}
			}

			Ok(())
		}

		pub fn start_default_host(&mut self, port: u16) -> io::Result<()> {
			self.start("0.0.0.0", port)
		}

		pub fn start_default_port(&mut self, host: &str) -> io::Result<()> {
			self.start(host, 0)
		}

		pub fn start_default(&mut self) -> io::Result<()> {
			self.start("0.0.0.0", 0)
		}

		pub fn stop(&mut self) -> io::Result<()> {
			if self.serving {
				self.serving = false;

				for (_, client) in &self.clients {
					match client {
						ClientSock::Sock(stream) => stream.shutdown(Shutdown::Both),
						ClientSock::Null => Ok(()),
					}?;
				}
			}

			Ok(())
		}

		fn serve(&mut self) -> io::Result<()> {
			match &self.sock {
				ServerSock::Sock(listener) => {
					listener.set_nonblocking(true)?;
					for stream in listener.incoming() {
						let result = match stream {
							Ok(conn) => {
								let client_id = self.clients.len();
								self.exchange_keys(client_id, &conn)?;
								self.clients.insert(client_id, ClientSock::Sock(conn));
								self.serve_client(client_id); // TODO: spawn new thread for this
								Ok(())
							},
							Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
								if self.serving {
									Ok(())
								} else {
									Err(io::Error::new(io::ErrorKind::Other, "Done"))
								}
							},
							Err(e) => Err(e),
						};

						if result.is_err() {
							let result_err = result.err().unwrap();
							if result_err.kind() == io::ErrorKind::Other {
								return Ok(());
							} else {
								return Err(result_err);
							}
						}

						thread::sleep(Duration::from_millis(10));
					}

					Ok(()) // unreachable; to satisfy the compiler
				},
				ServerSock::Null => Ok(()),
			}
		}

		fn exchange_keys(&self, client_id: usize, conn: &TcpStream) -> io::Result<()> {
			// TODO: implement key exchange
			Ok(())
		}

		fn serve_client(&self, client_id: usize) {
			// TODO: implement client serving
		}

		pub fn send(&self, data: &str, client_id: usize) -> io::Result<()> {
			if self.serving {
				// TODO: implement sending data
				Ok(())
			} else {
				Err(io::Error::new(io::ErrorKind::NotConnected, "The server is not serving"))
			}
		}

		pub fn send_multiple(&self, data: &str, client_ids: &[usize]) -> io::Result<()> {
			for client_id in client_ids {
				self.send(data, *client_id)?;
			}
			Ok(())
		}

		pub fn send_all(&self, data: &str) -> io::Result<()> {
			for (client_id, _) in &self.clients {
				self.send(data, *client_id)?;
			}
			Ok(())
		}

		pub fn serving(&self) -> bool {
			self.serving
		}

		pub fn get_addr(&self) -> io::Result<SocketAddr> {
			if self.serving {
				match &self.sock {
					ServerSock::Sock(listener) => listener.local_addr(),
					ServerSock::Null => Err(io::Error::new(io::ErrorKind::NotConnected, "The server is not listening")),
				}
			} else {
				Err(io::Error::new(io::ErrorKind::NotConnected, "The server is not serving"))
			}
		}

		pub fn get_client_addr(&self, client_id: usize) -> io::Result<SocketAddr> {
			if self.serving {
				match self.clients.get(&client_id) {
					Some(client) => {
						match client {
							ClientSock::Sock(conn) => conn.peer_addr(),
							ClientSock::Null => Err(io::Error::new(io::ErrorKind::Other, "Null client")) // this should not happen
						}
					},
					None => Err(io::Error::new(io::ErrorKind::NotFound, "Invalid client ID")),
				}
			} else {
				Err(io::Error::new(io::ErrorKind::NotConnected, "The server is not serving"))
			}
		}

		pub fn remove_client(&self, client_id: usize) -> io::Result<()> {
			if self.serving {
				match self.clients.get(&client_id) {
					Some(client) => {
						match client {
							ClientSock::Sock(conn) => conn.shutdown(Shutdown::Both),
							ClientSock::Null => Err(io::Error::new(io::ErrorKind::Other, "Null client")) // this should not happen
						}
					},
					None => Err(io::Error::new(io::ErrorKind::NotFound, "Invalid client ID"))
				}
			} else {
				Err(io::Error::new(io::ErrorKind::NotConnected, "The server is not serving"))
			}
		}
	}
}
