.PHONY: build release clean check test test-fast fix

build:
	cargo build

release:
	cargo build --release

clean:
	cargo clean

test:
	cargo test -- --quiet

test-fast:
	cargo test --lib -- --quiet

check:
	cargo fmt --check
	cargo clippy -- -D warnings
	cargo test -- --quiet
	cargo build

fix:
	cargo fmt
	cargo clippy --fix --allow-dirty --allow-staged
