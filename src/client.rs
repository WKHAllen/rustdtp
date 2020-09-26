#[path = "util.rs"]
mod util;

pub mod client {
	use std::net::{TcpStream, Shutdown};
	use std::io;
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

			// TODO: exchange keys
			// TODO: handle received data

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
			match &self.sock {
				Some(conn) => conn.shutdown(Shutdown::Both),
				None => unreachable!(),
			}
		}
	}
}
