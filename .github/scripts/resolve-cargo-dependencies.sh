#!/usr/bin/env bash
set -euo pipefail

cargo update -p native-tls

# This repository does not commit Cargo.lock. Keep recently published transitive
# releases outside Socket's package cooldown window when CI resolves the graph.
cargo update -p cfg-if --precise 1.0.4
cargo update -p cc --precise 1.4.5
cargo update -p const-hex --precise 1.19.1
cargo update -p derive-where --precise 1.6.1
cargo update -p lru-slab --precise 0.1.2
cargo update -p unicode-ident --precise 1.0.24
cargo update -p syn@3.0.6 --precise 3.0.5
cargo update -p zerofrom-derive --precise 0.1.7
cargo update -p rustix@1.1.5 --precise 1.1.4
cargo update -p smallvec --precise 1.16.0
cargo update -p jiff --precise 0.2.35
cargo update -p tinyvec --precise 1.13.2
cargo update -p yoke-derive --precise 0.8.2
cargo update -p libredox --precise 0.1.23
cargo update -p toml --precise 1.1.5+spec-1.1.0
cargo update -p toml_edit --precise 0.25.13+spec-1.1.0
cargo update -p jiff-core --precise 0.1.0
cargo update -p quinn --precise 0.11.11
cargo update -p quinn-proto --precise 0.11.17
