pub mod client {
	pub struct Client {
		on_recv: fn(&[u8]),
		on_disconnected: fn(),
		connected: bool,
		// TODO: add other attributes
	}

	// TODO: add implementation
}
