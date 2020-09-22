#[path = "util.rs"]
mod util;

pub mod server {
	use std::net::{TcpListener, TcpStream, Shutdown, SocketAddr};
	use std::thread;
	use std::collections::HashMap;
	use std::io;
	use std::io::{Read, Write};
	use std::time::Duration;
	use super::util::*;

	pub struct Server {
		on_recv: fn(usize, &[u8]),
		on_connect: fn(usize),
		on_disconnect: fn(usize),
		serving: bool,
		next_client_id: usize,
		sock: Option<TcpListener>,
		clients: HashMap<usize, TcpStream>,
		// TODO: add keys attribute
		// TODO: add other attributes
	}

	impl Server {
		pub fn new(
			on_recv: fn(usize, &[u8]),
			on_connect: fn(usize),
			on_disconnect: fn(usize),
				) -> Server {
			Server {
				on_recv,
				on_connect,
				on_disconnect,
				serving: false,
				next_client_id: 0,
				sock: None,
				clients: HashMap::new(),
			}
		}

		pub fn start(&mut self, host: &str, port: u16) -> io::Result<()> {
			if !self.serving {
				let addr = format!("{}:{}", host, port);
				let listener = TcpListener::bind(addr)?;
				self.sock = Some(listener);

				self.serving = true;
				self.serve()?;
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
					client.shutdown(Shutdown::Both)?;
				}
			}

			Ok(())
		}

		fn serve(&mut self) -> io::Result<()> {
			match &self.sock {
				Some(listener) => {
					listener.set_nonblocking(true)?;
					for stream in listener.incoming() {
						let result = match stream {
							Ok(conn) => {
								let client_id = self.next_client_id;
								self.next_client_id += 1;
								conn.set_nonblocking(true)?;

								self.exchange_keys(client_id, &conn)?;
								self.clients.insert(client_id, conn);
								(self.on_connect)(client_id);
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

						self.serve_clients()?;

						thread::sleep(Duration::from_millis(10));
					}

					unreachable!();
				},
				None => unreachable!(),
			}
		}

		fn exchange_keys(&self, client_id: usize, client: &TcpStream) -> io::Result<()> {
			// TODO: implement key exchange
			Ok(())
		}

		fn serve_client(&self, client_id: usize) -> io::Result<()> {
			match self.clients.get(&client_id) {
				Some(mut client) => {
					let mut size_buffer = [0; LEN_SIZE];
					let result = match client.read(&mut size_buffer) {
						Ok(size_len) => {
							assert_eq!(size_len, LEN_SIZE);
							
							let msg_size = ascii_to_dec(size_buffer);
							let mut buffer = Vec::with_capacity(msg_size);
							
							match client.read(&mut buffer) {
								Ok(len) => {
									assert_eq!(len, msg_size);

									// TODO: decrypt data
									let msg = buffer.as_slice();
									(self.on_recv)(client_id, msg);
									Ok(())
								},
								Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
									if self.serving {
										Ok(())
									} else {
										Err(io::Error::new(io::ErrorKind::Other, "Done"))
									}
								},
								Err(e) => {
									Err(e) // TODO: check for client disconnected
								},
							}
						},
						Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
							if self.serving {
								Ok(())
							} else {
								Err(io::Error::new(io::ErrorKind::Other, "Done"))
							}
						},
						Err(e) => {
							Err(e) // TODO: check for client disconnected
						},
					};

					if result.is_err() {
						let result_err = result.err().unwrap();
						if result_err.kind() == io::ErrorKind::Other {
							return Ok(());
						} else {
							return Err(result_err);
						}
					}

					Ok(())
				},
				None => Err(io::Error::new(io::ErrorKind::NotFound, "Invalid client ID")),
			}
		}
		
		fn serve_clients(&self) -> io::Result<()> {
			for (client_id, _) in &self.clients {
				self.serve_client(*client_id)?;
			}
			Ok(())
		}

		pub fn send(&self, data: &[u8], client_id: usize) -> io::Result<()> {
			if self.serving {
				match self.clients.get(&client_id) {
					Some(mut client) => {
						// TODO: encrypt data
						let size = dec_to_ascii(data);
						let mut buffer = vec![];
						buffer.extend_from_slice(&size);
						buffer.extend_from_slice(data);

						client.write(&buffer[..])?;
						Ok(())
					},
					None => Err(io::Error::new(io::ErrorKind::NotFound, "Invalid client ID")),
				}
			} else {
				Err(io::Error::new(io::ErrorKind::NotConnected, "The server is not serving"))
			}
		}

		pub fn send_multiple(&self, data: &[u8], client_ids: &[usize]) -> io::Result<()> {
			for client_id in client_ids {
				self.send(data, *client_id)?;
			}
			Ok(())
		}

		pub fn send_all(&self, data: &[u8]) -> io::Result<()> {
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
					Some(listener) => listener.local_addr(),
					None => Err(io::Error::new(io::ErrorKind::NotConnected, "The server is not listening")),
				}
			} else {
				Err(io::Error::new(io::ErrorKind::NotConnected, "The server is not serving"))
			}
		}

		pub fn get_client_addr(&self, client_id: usize) -> io::Result<SocketAddr> {
			if self.serving {
				match self.clients.get(&client_id) {
					Some(client) => client.peer_addr(),
					None => Err(io::Error::new(io::ErrorKind::NotFound, "Invalid client ID")),
				}
			} else {
				Err(io::Error::new(io::ErrorKind::NotConnected, "The server is not serving"))
			}
		}

		pub fn remove_client(&mut self, client_id: usize) -> io::Result<()> {
			if self.serving {
				match self.clients.get(&client_id) {
					Some(client) => {
						client.shutdown(Shutdown::Both)?;
						self.clients.remove(&client_id);
						// TODO: remove client's key
						Ok(())
					},
					None => Err(io::Error::new(io::ErrorKind::NotFound, "Invalid client ID"))
				}
			} else {
				Err(io::Error::new(io::ErrorKind::NotConnected, "The server is not serving"))
			}
		}
	}

	impl Drop for Server {
		fn drop(&mut self) {
			self.stop().unwrap();
		}
	}
}
