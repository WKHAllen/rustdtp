pub mod client {
	pub struct Client {
		on_recv: fn(&[u8]),
		on_disconnected: fn(),
		blocking: bool,
		event_blocking: bool,
		connected: bool,
		// TODO: add other attributes
	}

	// TODO: add implementation
}
