.PHONY: build fmt check clean

build:
	cargo build --release

fmt:
	cargo fmt

check:
	cargo check
	cargo clippy -- -D warnings

clean:
	cargo clean

test:
	cargo test