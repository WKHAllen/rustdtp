#[path = "util.rs"]
mod util;

pub mod client {
	use super::util::*;
	use std::io;
	use std::io::{Read, Write};
	use std::net::{Shutdown, SocketAddr, TcpStream};
	use std::thread;
	use std::time::Duration;

	type OnRecvFunc<T> = fn(&[u8], &T);
	type OnDisconnectedFunc<U> = fn(&U);

	pub struct Client<'a, T, U: 'a> {
		on_recv: OnRecvFunc<T>,
		on_disconnected: OnDisconnectedFunc<U>,
		on_recv_arg: &'a T,
		on_disconnected_arg: &'a U,
		connected: bool,
		sock: Option<TcpStream>,
		// TODO: add other attributes
	}

	impl<'a, T, U> Client<'a, T, U> {
		pub fn new(
			on_recv: OnRecvFunc<T>,
			on_disconnected: OnDisconnectedFunc<U>,
			on_recv_arg: &'a T,
			on_disconnected_arg: &'a U,
		) -> Client<'a, T, U> {
			Client {
				on_recv,
				on_disconnected,
				on_recv_arg,
				on_disconnected_arg,
				connected: false,
				sock: None,
			}
		}

		pub fn connect(&mut self, host: &str, port: u16) -> io::Result<()> {
			if self.connected {
				return Err(io::Error::new(io::ErrorKind::Other, "Already connected"));
			}

			let addr = format!("{}:{}", host, port);
			let stream = TcpStream::connect(addr)?;

			self.sock = Some(stream);
			self.connected = true;

			self.exchange_keys()?;
			self.handle()?;

			Ok(())
		}

		pub fn connect_default_host(&mut self, port: u16) -> io::Result<()> {
			self.connect("0.0.0.0", port)
		}

		pub fn disconnect(&mut self) -> io::Result<()> {
			if !self.connected {
				return Err(io::Error::new(io::ErrorKind::Other, "Not connected"));
			}

			self.connected = false;
			self.sock.as_ref().unwrap().shutdown(Shutdown::Both)
		}

		fn handle(&self) -> io::Result<()> {
			let mut conn = self.sock.as_ref().unwrap();
			conn.set_nonblocking(true)?;

			loop {
				let mut size_buffer = [0; LEN_SIZE];
				let result = match conn.read(&mut size_buffer) {
					Ok(size_len) => {
						assert_eq!(size_len, LEN_SIZE);

						let msg_size = ascii_to_dec(size_buffer);
						let mut buffer = Vec::with_capacity(msg_size);

						match conn.read(&mut buffer) {
							Ok(len) => {
								assert_eq!(len, msg_size);

								// TODO: decrypt data
								let msg = buffer.as_slice();
								(self.on_recv)(msg, self.on_recv_arg);
								Ok(())
							}
							Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
								if self.connected {
									Ok(())
								} else {
									Err(io::Error::new(io::ErrorKind::Other, "Done"))
								}
							}
							Err(e) => {
								Err(e) // TODO: check for disconnected
							}
						}
					}
					Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
						if self.connected {
							Ok(())
						} else {
							Err(io::Error::new(io::ErrorKind::Other, "Done"))
						}
					}
					Err(e) => {
						Err(e) // TODO: check for disconnected
					}
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
		}

		fn exchange_keys(&mut self) -> io::Result<()> {
			// TODO: implement key exchange
			Ok(())
		}

		pub fn send(&self, data: &[u8]) -> io::Result<()> {
			if !self.connected {
				return Err(io::Error::new(io::ErrorKind::Other, "Not connected"));
			}

			// TODO: encrypt data
			let size = dec_to_ascii(data.len());
			let mut buffer = vec![];
			buffer.extend_from_slice(&size);
			buffer.extend_from_slice(data);

			let mut conn = self.sock.as_ref().unwrap();
			conn.write(&buffer[..])?;
			Ok(())
		}

		pub fn connected(&self) -> bool {
			self.connected
		}

		pub fn get_addr(&self) -> io::Result<SocketAddr> {
			if !self.connected {
				return Err(io::Error::new(io::ErrorKind::Other, "Not connected"));
			}

			let conn = self.sock.as_ref().unwrap();
			conn.local_addr()
		}

		pub fn get_server_addr(&self) -> io::Result<SocketAddr> {
			if !self.connected {
				return Err(io::Error::new(io::ErrorKind::Other, "Not connected"));
			}

			let conn = self.sock.as_ref().unwrap();
			conn.peer_addr()
		}
	}
}
