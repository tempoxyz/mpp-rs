.PHONY: build release clean check test test-fast test-integration fix

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

# Integration tests require a running Tempo localnet.
#   docker compose up -d
#   make test-integration
#   docker compose down
test-integration:
	cargo test --features integration --test integration_charge -- --nocapture

check:
	cargo fmt --check
	cargo clippy --all-features -- -D warnings
	cargo test -- --quiet
	cargo build

fix:
	cargo fmt
	cargo clippy --fix --allow-dirty --allow-staged
