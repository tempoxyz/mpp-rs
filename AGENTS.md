# mpp-rs

The Rust SDK for MPP, published to crates.io as the `mpp` crate. It covers both sides of a paid HTTP exchange: servers that issue Challenges and verify Credentials for Tempo (charge and session) and Stripe (charge), and clients that answer `402` responses automatically, plus WebSocket, MCP, Tower and Axum integrations. User-facing usage and feature flags are in [README.md](./README.md).

## Commands

```bash
cargo fmt --all -- --check                                      # format
cargo clippy --workspace --all-targets --all-features -- -D warnings   # lint
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo doc --no-deps --all-features   # docs build without warnings
sg scan -c sgconfig.yml src/ && sg test -c sgconfig.yml         # ast-grep rules (ast-grep 0.45)
typos                                                           # spelling (_typos.toml)
cargo test --lib --bins --tests --features tempo,stripe,ws,server,client,axum,middleware,tower,utils,sqlite,integration-stripe,integration-ws   # unit and offline integration tests
cargo test --doc --features tempo,stripe,ws,server,client,axum,middleware,tower,utils,sqlite,integration-stripe,integration-ws   # doc tests
cargo check --workspace --exclude mpp                           # examples and alloy-transport-mpp
cargo hack check --feature-powerset --depth 2 --no-dev-deps --skip integration,integration-stripe,integration-ws --exclude-features reqwest-default-tls,reqwest-native-tls,reqwest-rustls-tls,reqwest-rustls-tls-no-provider   # feature combinations
cargo deny check                                                # licenses and advisories (deny.toml)
```

A bare `cargo test` builds only the default features and skips most of the suite: pass the feature list above. Run one test with `cargo test --features <list> <test_name>`, or one file with `--test <file>` (for example `--test integration_ws`). `make check` and `make fix` are local shortcuts for fmt, clippy and tests.

`integration_charge` and `integration_session` need a Tempo localnet from Docker: `docker compose up -d --wait`, then `cargo test --features integration --test integration_charge --test integration_session -- --nocapture`, then `docker compose down`. `integration_stripe` uses a mock Stripe API; its live tests skip unless `STRIPE_SECRET_KEY` is set. `integration_ws`, `tower_layer`, `problem_details` and `sqlite_interop` run offline. Fuzzing needs nightly and cargo-fuzz: `fuzz/run-all.sh [seconds-per-target]` (see [fuzz/README.md](./fuzz/README.md)).

## Layout

- `src/protocol/core/`: Challenge, Credential and Receipt types, header parsing and formatting, `Accept-Payment`, and Challenge ID binding (`binding.rs`: `compute_challenge_id`, `constant_time_eq`).
- `src/protocol/intents/`, `src/protocol/methods/{tempo,stripe}/`, `src/protocol/traits/`: intent requests, method schemas (Tempo transactions, vouchers, fee payers, proofs) and the `ChargeMethod`/session traits.
- `src/server/`: the `Mpp` server (`mpp/issue.rs`, `mpp/verify.rs`, `mpp/session.rs`), Tempo and Stripe methods, Axum extractors, Tower middleware, SSE, metering and WebSocket sessions.
- `src/client/`: `PaymentProvider`s for Tempo and Stripe, the `Fetch` extension, reqwest `PaymentMiddleware`, Challenge selection, `AcceptPaymentPolicy`, the forward proxy and the WebSocket client.
- `src/mcp.rs`, `src/mcp/`: the MCP transport. `src/proxy/`: the paid-API proxy service. `src/store.rs`: `Store`, `MemoryStore`, `FileStore`; the client session store, with SQLite behind `sqlite`, is in `src/client/tempo/session/store.rs`.
- `crates/alloy-transport-mpp/`: Alloy HTTP and WebSocket transports that pay for RPC (`publish = false`).
- `examples/`: workspace example crates (basic, axum-extractor, catalog-client, charge-relay, session, stripe, ws).
- `tests/`: integration tests; `tests/fixtures/` holds binary fixtures. Unit tests live next to the code (`#[cfg(test)]` and `tests.rs` modules).
- `fuzz/`: cargo-fuzz targets for every parser of untrusted input, with seeds and a dictionary.
- `rules/`, `ast-grep-tests/`: ast-grep lint rules and their tests.
- `.changelog/`: pending changelog fragments and `config.toml`.

## Conventions

- Features gate everything beyond the core types: `client`, `server`, `tempo` (implies `evm`), `stripe`, `middleware`, `tower`, `axum`, `ws`, `sqlite`, `utils`, `forward-proxy` and the `reqwest-*-tls` backends. New code compiles under every pairing of features (`cargo hack` above); put it behind the narrowest feature that needs it.
- Compare HMACs and Challenge IDs with `constant_time_eq`, never `==` or `!=`; the `no-hmac-equality-compare` ast-grep rule enforces it.
- Match mppx's names, defaults and errors. Behavior ported from mppx says so in the changelog (for example "as mppx does").
- Payment helpers pay only when a request authorizes it (`AcceptPaymentPolicy::Explicit` by default) and verification takes the route's amount; keep both when changing client or server flows.
- Every user-visible change needs a changelog fragment in `.changelog/<random-name>.md` (`changelogs add`, or the suggestion the Changelog workflow comments on the pull request):

  ```markdown
  ---
  mpp: patch
  ---

  Added ... / Fixed ... (past tense, user-facing).
  ```

  Bump with `patch` for fixes and additive changes and `minor` for breaking ones while the crate is pre-1.0. Docs-only and CI-only changes need none.
- Commits and pull request titles use Conventional Commits (`feat(tempo): ...`, `fix: ...`, `!` for breaking); the release workflow reads them.
- mpp-tools' daily SDK Conformance Monitor runs the cross-SDK conformance suite against `main` with the `rust` adapter and opens a `conformance-failure` issue in tempoxyz/mpp-tools when it fails; this repository's CI does not run it. Protocol changes add or update vectors there.

## Releases

Releases use [changelogs](https://github.com/tempoxyz/changelogs). A push to main opens or updates a "Version Packages" pull request that bumps `Cargo.toml` and writes `CHANGELOG.md` from the fragments; merging it publishes to crates.io and tags `mpp@x.y.z`. A Monday 15:17 UTC run sets that pull request to auto-merge. Never edit `CHANGELOG.md` or the crate version by hand. Details are in [RELEASE.md](./RELEASE.md).

<!-- BEGIN MPP SHARED: synced from tempoxyz/mpp-tools agents/shared.md. Edit it there; changes here are overwritten. -->

## MPP

Conventions every MPP repository shares, pulled together from their AGENTS.md files. Synced from [`agents/shared.md`](https://github.com/tempoxyz/mpp-tools/blob/main/agents/shared.md) in tempoxyz/mpp-tools: edit it there. The sections above it are this repository's own and win where they are more specific.

### This file

- Keep it to `# <repository>` and a short paragraph, then `## Commands`, `## Layout`, `## Conventions`, then only the sections this repository needs, then this section.
- Write rules an agent can act on: commands, paths, constraints. Leave out background, history and anything the code, specs or README already say.
- When you learn a convention the hard way, add it to the section it belongs to in the same pull request.

### Code

- Make the smallest change that does the job and follow the surrounding code. Start concrete; extract an abstraction only once several real uses share it.
- Keep the public API narrow. Add rather than remove or rename, and mark what you replace as deprecated before deleting it.
- Document every exported item (JSDoc, rustdoc, docstrings, Go doc comments). Comments say why, not what.
- Match mppx, the reference SDK: its names (Challenge, Credential, Receipt, Method), defaults, errors and behavior, unless the language forces otherwise; say why when it does.
- The IETF drafts in tempoxyz/mpp-specs (paymentauth.org) are the source of truth for the protocol, and mppx settles what they leave open. Link them instead of restating them.
- Add no dependency without a reason the pull request states. Prefer the standard library and what the repository already uses.
- Never log or commit keys, credentials, signatures, authorization headers or raw upstream errors.
- Tempo chain IDs: mainnet `4217`, Moderato testnet `42431`. Never `98865`.

### Tooling

Use each language's standard toolchain, run through the commands in `## Commands`, and keep it clean with warnings as errors:

- TypeScript: pnpm, strict `tsc`, ESM with `.js` relative imports, the repository's configured formatter and linter, Vitest.
- Python: uv, ruff (format and lint), a strict type checker (pyright or ty), pytest or unittest.
- Rust: cargo, `cargo fmt`, `cargo clippy -D warnings`, `cargo test`.
- Go: `gofmt`, `go vet`, golangci-lint, `go test -race`.
- Swift: SwiftPM, `swift test -Xswiftc -warnings-as-errors`.
- Run the checks that cover your change before opening a pull request, and add tests for behavior that matters, next to the existing ones.
- Pin GitHub Actions by full commit SHA. Workflows start with `tempoxyz/gh-actions/actions/secure-runner` and get write tokens from GitHub STS policies in `.github/sts/`, never stored secrets.

### Changes

- Commits and pull request titles use Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, optionally scoped.
- Never edit `CHANGELOG.md` by hand. Record a release note the way `## Conventions` says (changeset, `.changelog/` fragment, or none when a workflow writes it), in the past tense.
- Before 1.0, bump `patch` for everything except a breaking public API change, which is `minor`.
- Don't edit README files unless asked.
- Never force-push.

### Docs and prose

- Active voice, present tense, second person. Sentence-case headings. No filler (just, simply, easily) and no Latin abbreviations.
- Capitalize Challenge, Credential and Receipt as MPP concepts. Say stablecoins, not crypto, and USDC.e for bridged USDC on Tempo. Write `mppx` in lowercase.

<!-- END MPP SHARED -->
