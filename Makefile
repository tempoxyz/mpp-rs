.PHONY: build release clean check test test-fast fix fuzz fuzz-www-authenticate fuzz-authorization fuzz-receipt fuzz-base64url

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
	cargo clippy --all-features -- -D warnings
	cargo test -- --quiet
	cargo build

fix:
	cargo fmt
	cargo clippy --fix --allow-dirty --allow-staged

# Fuzz testing targets (requires: cargo install cargo-fuzz && rustup install nightly)
fuzz-www-authenticate:
	cargo +nightly fuzz run fuzz_www_authenticate

fuzz-authorization:
	cargo +nightly fuzz run fuzz_authorization

fuzz-receipt:
	cargo +nightly fuzz run fuzz_receipt

fuzz-base64url:
	cargo +nightly fuzz run fuzz_base64url_json

# Run all fuzz targets briefly (1000 runs each) for CI smoke testing
fuzz-check:
	cargo +nightly fuzz run fuzz_www_authenticate -- -runs=1000
	cargo +nightly fuzz run fuzz_authorization -- -runs=1000
	cargo +nightly fuzz run fuzz_receipt -- -runs=1000
	cargo +nightly fuzz run fuzz_base64url_json -- -runs=1000
