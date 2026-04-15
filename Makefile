.PHONY: build check clippy test clean

build:
	cargo build --locked

check:
	cargo check --locked

clippy:
	cargo clippy --locked

test:
	cargo test --locked

clean:
	cargo clean
