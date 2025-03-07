all: build

build:
	cargo build

test:
	cargo test -- --nocapture

lint:
	cargo clippy -- -D warnings

docs:
	cargo doc --open

clean:
	cargo clean
