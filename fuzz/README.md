# Fuzz Testing for mpp

This directory contains fuzz testing harnesses for the mpp library, targeting the header parsing functions which handle untrusted input.

## Fuzz Targets

| Target | Function | Purpose |
|--------|----------|---------|
| `fuzz_www_authenticate` | `parse_www_authenticate()` | WWW-Authenticate header parsing |
| `fuzz_authorization` | `parse_authorization()` | Authorization header parsing (base64 + JSON) |
| `fuzz_receipt` | `parse_receipt()` | Payment-Receipt header parsing |
| `fuzz_base64url_json` | `Base64UrlJson::decode()` | Base64url JSON decoding |

## Prerequisites

```bash
# Install nightly toolchain
rustup install nightly

# Install cargo-fuzz
cargo install cargo-fuzz
```

## Running Fuzz Tests

```bash
# Run a specific fuzz target
cargo +nightly fuzz run fuzz_www_authenticate

# Run with a timeout per test case (10 seconds)
cargo +nightly fuzz run fuzz_www_authenticate -- -timeout=10

# Run for a limited number of iterations
cargo +nightly fuzz run fuzz_www_authenticate -- -runs=100000

# Run without sanitizers (faster, for safe Rust)
cargo +nightly fuzz run --sanitizer none fuzz_www_authenticate
```

## Corpus

Seed corpus files are stored in `fuzz/corpus/<target>/`. To seed the corpus with example headers:

```bash
mkdir -p fuzz/corpus/fuzz_www_authenticate
echo -n 'Payment id="abc", realm="api", method="tempo", intent="charge", request="e30"' > fuzz/corpus/fuzz_www_authenticate/valid_header
```

## Coverage

To generate coverage reports:

```bash
cargo +nightly fuzz coverage fuzz_www_authenticate
```

## Found Issues

Crashes are saved to `fuzz/artifacts/<target>/`. To reproduce a crash:

```bash
cargo +nightly fuzz run fuzz_www_authenticate fuzz/artifacts/fuzz_www_authenticate/crash-<hash>
```
