all: build

build:
	cargo build

test:
	cargo test -- --nocapture

lint:
	cargo clippy -- -D warnings

clean:
	cargo clean
