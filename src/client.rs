use crate::util::*;
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

pub struct Client<R, D>
where
	R: Fn(&[u8]) + Clone,
	D: Fn() + Clone,
{
	on_receive: Option<R>,
	on_disconnected: Option<D>,
	connected: bool,
	sock: Option<TcpStream>,
	// TODO: add other attributes
}

impl<R, D> Client<R, D>
where
	R: Fn(&[u8]) + Clone,
	D: Fn() + Clone,
{
	pub fn new() -> ClientBuilder<R, D> {
		ClientBuilder::new()
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
		self.handle()
	}

	pub fn connect_default_host(&mut self, port: u16) -> io::Result<()> {
		self.connect(DEFAULT_HOST, port)
	}

	pub fn connect_default_port(&mut self, host: &str) -> io::Result<()> {
		self.connect(host, DEFAULT_PORT)
	}

	pub fn connect_default(&mut self) -> io::Result<()> {
		self.connect(DEFAULT_HOST, DEFAULT_PORT)
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

					let msg_size = decode_message_size(size_buffer);
					let mut buffer = Vec::with_capacity(msg_size);

					match conn.read(&mut buffer) {
						Ok(len) => {
							assert_eq!(len, msg_size);

							// TODO: decrypt data
							let msg = buffer.as_slice();

							match &self.on_receive {
								Some(on_receive) => on_receive(msg),
								None => (),
							}

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
		let size = encode_message_size(data.len());
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

impl<R, D> Drop for Client<R, D>
where
	R: Fn(&[u8]) + Clone,
	D: Fn() + Clone,
{
	fn drop(&mut self) {
		if self.connected {
			self.disconnect().unwrap();
		}
	}
}

pub struct ClientBuilder<R, D>
where
	R: Fn(&[u8]) + Clone,
	D: Fn() + Clone,
{
	on_receive: Option<R>,
	on_disconnected: Option<D>,
	blocking: bool,
}

impl<R, D> ClientBuilder<R, D>
where
	R: Fn(&[u8]) + Clone,
	D: Fn() + Clone,
{
	pub fn new() -> Self {
		Self {
			on_receive: None,
			on_disconnected: None,
			blocking: false,
		}
	}

	pub fn build(&self) -> Client<R, D> {
		Client {
			on_receive: self.on_receive.clone(),
			on_disconnected: self.on_disconnected.clone(),
			connected: false,
			sock: None,
		}
	}

	pub fn on_receive(&mut self, on_receive: R) -> &mut Self {
		self.on_receive = Some(on_receive);
		self
	}

	pub fn on_disconnected(&mut self, on_disconnected: D) -> &mut Self {
		self.on_disconnected = Some(on_disconnected);
		self
	}

	pub fn blocking(&mut self) -> &mut Self {
		self.blocking = true;
		self
	}
}
