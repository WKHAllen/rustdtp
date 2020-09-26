#[path = "util.rs"]
mod util;

pub mod client {
	use std::net::{TcpStream, Shutdown};
	use std::io;
	use std::io::{Read, Write};
	use std::thread;
	use std::time::Duration;
	use super::util::*;

	pub struct Client {
		on_recv: fn(&[u8]),
		on_disconnected: fn(),
		connected: bool,
		sock: Option<TcpStream>,
		// TODO: add other attributes
	}

	impl Client {
		pub fn new(
			on_recv: fn(&[u8]),
			on_disconnected: fn()
				) -> Client {
			Client {
				on_recv,
				on_disconnected,
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
								(self.on_recv)(msg);
								Ok(())
							},
							Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
								if self.connected {
									Ok(())
								} else {
									Err(io::Error::new(io::ErrorKind::Other, "Done"))
								}
							},
							Err(e) => {
								Err(e) // TODO: check for disconnected
							},
						}
					},
					Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
						if self.connected {
							Ok(())
						} else {
							Err(io::Error::new(io::ErrorKind::Other, "Done"))
						}
					},
					Err(e) => {
						Err(e) // TODO: check for disconnected
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
	}
}
