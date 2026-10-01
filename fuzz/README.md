# Fuzz testing for mpp

Fuzz targets for the code that handles untrusted input: header parsers, the
JSON carried in credentials and receipts, MCP metadata, SSE events and the
Tempo decoders. Every target asserts invariants (round trips, agreement
between two implementations, binding properties), not just the absence of
panics.

## Targets

| Target | Input | Invariants |
|--------|-------|------------|
| `fuzz_www_authenticate` | text | `parse_www_authenticate` and `parse_www_authenticate_all` never panic; an accepted header formats and parses back to the same challenge; both parsers agree on a header that names the scheme once |
| `fuzz_challenge_roundtrip` | structured challenge | formatted headers are printable ASCII; every challenge the formatter accepts parses back field for field |
| `fuzz_challenge_list` | 1–5 challenges, decoy schemes, separators | `parse_www_authenticate_all` returns exactly the Payment challenges, in order, among `Basic`/`Bearer`/`Digest` challenges whose quoted values look like Payment ones |
| `fuzz_challenge_id` | structured challenge, field mutations | a signed challenge verifies, also through the header and the credential echo; changing a bound field or the id fails verification |
| `fuzz_authorization` | text, as header and as credential JSON | `parse_authorization` and `extract_payment_scheme` never panic; an accepted credential formats and parses back unchanged |
| `fuzz_credential_roundtrip` | structured credential | every credential the formatter accepts parses back field for field, also next to other schemes |
| `fuzz_receipt` | text, as header and as receipt JSON | `parse_receipt` never panics; accepted receipts are successful with an RFC 3339 timestamp and round-trip with their extension fields; `Receipt::success` round-trips |
| `fuzz_base64url_json` | bytes | encode/decode round trip; the lenient decoder agrees with the strict engines and has one canonical spelling per input; `Base64UrlJson::from_value` is idempotent |
| `fuzz_accept_payment` | text | `parse` never panics; `parse(serialize(e)) == e`; `rank` matches a reference implementation of the ranking rule |
| `fuzz_amount` | amount strings, splits | the amount parsers agree; `parse_units` returns canonical integers and scales by ten; split transfers sum to the total |
| `fuzz_mcp` | structured challenge and credential, JSON mutation | challenges, credentials and receipts survive the MCP helpers unchanged; the extractors never panic on mutated metadata |
| `fuzz_sse_event` | text | `parse_event` never panics; message, need-voucher and receipt events round-trip with any content |
| `fuzz_fee_payer_envelope` | bytes | `decode_envelope` never panics; decode → encode → decode is stable |
| `fuzz_attribution` | memo bytes, ids | `decode` agrees with `is_mpp_memo`; an encoded memo verifies only against its own server and challenge |
| `fuzz_session_payload` | JSON text | Tempo session and charge payloads deserialize without panicking and re-serialize to the same value |
| `fuzz_voucher_signature` | signature mutations, voucher fields | `verify_voucher` accepts exactly the canonical 65-byte and ERC-2098 signatures of the signed voucher |

`fuzz_sse_event` needs `--features server`; the last four targets, the
receipt event in `fuzz_sse_event`, and the `U256` and split checks in
`fuzz_amount` need `--features tempo`.

Shared input generators and comparison helpers live in `src/lib.rs`.

## Prerequisites

```bash
rustup install nightly
cargo install cargo-fuzz --locked
```

## Running

```bash
# One target, with its seeds and dictionary
cargo +nightly fuzz run fuzz_www_authenticate \
  fuzz/corpus/fuzz_www_authenticate fuzz/seeds/fuzz_www_authenticate \
  -- -dict=fuzz/dict/http.dict

# A target that needs Tempo
cargo +nightly fuzz run --features tempo fuzz_fee_payer_envelope \
  fuzz/corpus/fuzz_fee_payer_envelope fuzz/seeds/fuzz_fee_payer_envelope

# Every target for 60 seconds each, four at a time
FUZZ_JOBS=4 fuzz/run-all.sh 60

# A subset
fuzz/run-all.sh 300 fuzz_challenge_list fuzz_mcp

# Long runs: without the address sanitizer (faster, less memory)
cargo +nightly fuzz run --sanitizer none fuzz_challenge_list
```

`run-all.sh` builds with `--features tempo`, passes each target its seeds and
dictionary, and exits non-zero if a target crashes. CI runs it for 30 seconds
per target on every pull request (`.github/workflows/fuzz.yml`).

## Seeds and dictionaries

`fuzz/seeds/<target>/` holds a small checked-in seed corpus for the targets
that take text or bytes; most header seeds are the `wire` values of the
conformance vectors. The targets that take structured input start from an
empty corpus. `fuzz/corpus/<target>/` is the working corpus that libFuzzer
grows; it is not checked in.

- `dict/http.dict`: auth-param names, quoted-string escapes, list separators,
  `Accept-Payment` and SSE syntax.
- `dict/json.dict`: JSON syntax, numbers that stress canonicalization, and
  the member names of credentials, receipts and Tempo payloads.

## Crashes

Reproducers are saved to `fuzz/artifacts/<target>/`:

```bash
cargo +nightly fuzz run fuzz_www_authenticate fuzz/artifacts/fuzz_www_authenticate/crash-<hash>

# Print a structured input in readable form
cargo +nightly fuzz fmt fuzz_challenge_list fuzz/artifacts/fuzz_challenge_list/crash-<hash>

# Shrink it
cargo +nightly fuzz tmin fuzz_www_authenticate fuzz/artifacts/fuzz_www_authenticate/crash-<hash>
```

CI prints the reproducer as base64; decode it into a file to replay it:

```bash
echo '<base64>' | base64 -d > crash
cargo +nightly fuzz run --features tempo <target> crash
```

## Known gaps

Assertions that do not hold yet are narrowed in the target, with a comment at
the place:

- `format_www_authenticate` and `format_authorization` do not validate
  `expires` and `digest`; the parsers do. Such values format but do not parse
  back (`has_unparseable_optionals` in `src/lib.rs`).
- The challenge id joins its slots with `|` without escaping, so it is only
  injective for slots that do not contain `|` (`fuzz_challenge_id`).
- `parse_www_authenticate` trims Unicode whitespace before the scheme and
  `parse_www_authenticate_all` only SP and HTAB; an auth-param named
  `Payment` splits a challenge in the list parser (`fuzz_www_authenticate`).
- `accept_payment::parse` accepts exponent q-values such as `q=1e-5`, which
  the serializer writes as `q=0` (`fuzz_accept_payment`).
- The `u128` and `U256` amount parsers disagree outside plain digit strings
  (`+1`, `0x10`, `1_000`, the empty string). `--features strict-amounts`
  asserts that both accept only `0|[1-9][0-9]*` (`fuzz_amount`).
- JCS rounds integers beyond 2^53 (`fuzz_base64url_json`).

## Coverage

```bash
cargo +nightly fuzz coverage fuzz_www_authenticate fuzz/corpus/fuzz_www_authenticate
```
