.PHONY: build check clippy test clean install uninstall

build:
	cargo build --locked --release

check: clippy test

clippy:
	cargo clippy --locked

test:
	cargo test --locked

clean:
	cargo clean

install: build
	@scripts/install.sh install

uninstall:
	@scripts/install.sh uninstall
