# Changelog

## 0.15.1 (2026-10-09)

### Patch Changes

- Stopped WebSocket reconnects from renewing payment authorization after a charge or voucher attempt. Rejected custom-header payment challenges before credential creation when the caller's reqwest redirect policy cannot be verified, while selecting a safe alternative challenge when offered. (by @BrendanRyan, [#562](https://github.com/tempoxyz/mpp-rs/pull/562))
- Preserved the signed transaction gas limit in fallback pre-broadcast simulation. (by @BrendanRyan, [#562](https://github.com/tempoxyz/mpp-rs/pull/562))
- Reused the signed top-up transaction when retrying a refreshed challenge and enforced the local deposit cap before signing.
- Serialized top-ups with channel-store leases, reconciled deposits before enforcing caps, and rejected refreshed challenges that change sponsorship mode. (by @BrendanRyan, [#562](https://github.com/tempoxyz/mpp-rs/pull/562))

## 0.15.0 (2026-10-01)

### Minor Changes

- Fixed the direct server verification API accepting a credential on a route it was not paid for. `Mpp::verify_credential` and `compose_verify` only check that the handler issued the challenge, so on a handler serving several prices a credential for the cheapest route unlocked all of them. Added `Mpp::verify_charge` and `Mpp::stripe_verify_charge` (plus `_with_options` variants), which take the amount the route charges and reject credentials issued for anything else, `Mpp::expected_charge_request` and `Mpp::stripe_expected_charge_request` for the `*_with_expected_request` methods, and `compose_verify_with_expected_requests`. `Mpp::verify_credential`, `Mpp::verify_credential_with_body` and `compose_verify` are deprecated. To migrate, replace `mpp.verify_credential(&credential)` with `mpp.verify_charge(&credential, amount)`, passing the amount the route gives to `charge()`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `Mpp::create` accepting `.fee_payer(true)` with neither a fee payer signer nor a relay: every challenge advertised `feePayer: true` and every sponsored credential was then rejected. This configuration now fails with `InvalidConfig`. To migrate, add `.fee_payer_signer(...)` or `.relay(...)`, or drop `.fee_payer(true)`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the credential's challenge echo dropping `description`, and credentials whose echoed `opaque` uses the legacy object form sent by older mppx clients being rejected. `ChallengeEcho` has a new `description` field that `PaymentChallenge::to_echo` fills in, and an object-shaped `opaque` is normalized to its base64url string. Code that builds `ChallengeEcho` with a struct literal must add `description: None` (or use `to_echo`). (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- `PaymentMiddleware` now reports payment failures as `HttpError`, the error `Fetch` returns, inside `reqwest_middleware::Error::Middleware`. They used to be ad-hoc `anyhow` messages that callers could not match on. Code that downcast the middleware error to `MppError` should downcast to `HttpError` and match `HttpError::Payment`. The messages, including the `error` text of `payment.failed` events, now use the `HttpError` wording. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed weak HMAC secrets being accepted: `Mpp::create` and `Mpp::create_stripe` now return `InvalidConfig` when `MPP_SECRET_KEY` or `.secret_key(...)` is shorter than 32 bytes, as mppx does. To migrate, generate a key with `openssl rand -base64 32` and set it as `MPP_SECRET_KEY`; challenges issued under the old key no longer verify, so clients holding one are challenged again. `Mpp::new` and the challenge helpers cannot fail and do not check the length. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `sse::serve` and `ws_session` repeating the need-voucher event on every poll tick and channel write while the balance was exhausted. It is now sent once per exhaustion, as mppx does, so clients no longer answer with duplicate vouchers. `requiredCumulative` now also clears the server's minimum voucher delta, so a stream no longer stalls when that delta is larger than the tick cost. `ServeOptions` and `WsSessionOptions` have a new required `min_voucher_delta` field: set it to the session method's `SessionMethodConfig::min_voucher_delta` (`0` if none is enforced). (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the problem types reported for payment failures. Malformed credentials now map to `malformed-credential` (402) instead of `internal-payment-error` or `invalid-challenge`, challenge-binding failures (unknown or tampered challenge id, missing or mismatched bound fields) map to `invalid-challenge` instead of `verification-failed`, and RPC, store and upstream API failures during verification map to `internal-payment-error` (500) instead of `verification-failed` (402). `internal-payment-error` problems now carry a fixed `detail` instead of the underlying error text, and `ErrorCode::spec_code()` returns the problem type that is actually reported.
- Migration: `ErrorCode` is now `#[non_exhaustive]` and gained `InvalidChallenge` and `Internal`, and `MppError` gained `Internal` and `InvalidReceipt`, so exhaustive matches need a wildcard arm. `Mpp::verify_*` reports binding failures with `ErrorCode::InvalidChallenge` instead of `ErrorCode::CredentialMismatch`, `parse_authorization` fails with `MppError::MalformedCredential`, and `parse_receipt` fails with `MppError::InvalidReceipt` instead of `MppError::InvalidChallenge`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the proxy's OpenAPI discovery document omitting the payment method. `proxy::PaidEndpoint` has a new `method` field, written as `method` in each `x-payment-info` offer (REQUIRED by the discovery spec) and in the `payment` object of `/services`.
- Migration: `PaidEndpoint` is now `#[non_exhaustive]`, so it can no longer be built with a struct literal. Use `PaidEndpoint::new(method, intent, amount)` and the `with_decimals`, `with_currency`, `with_unit_type` and `with_description` setters, e.g. `PaidEndpoint::new("tempo", "charge", "50000").with_decimals(6)`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the proxy injecting upstream headers in a random order. `proxy::Service::headers` was a `HashMap`, so the order changed from run to run, and `bearer(..)` followed by `header("authorization", ..)` kept both entries and let either one win. Headers are now injected in the order they were added, and adding a name again (in any letter case) replaces the earlier value.
- Migration: `Service::headers` is now a `Vec<(String, String)>`. Replace `service.headers.get(name)` with `service.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name))`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `TempoSessionProvider` enforcing `max_deposit` only when a voucher needed a top-up. A channel whose deposit is above the limit, e.g. one opened with a higher limit, restored from the channel store or recovered from the server, was spent up to its full deposit. Every voucher signed by `pay` is now checked, so such a payment fails with `exceeds local max_deposit`; raise `with_max_deposit` to keep spending from that channel. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed Tempo session actions returning a base receipt that session clients such as mppx reject. `SessionMethod` now returns spec-shaped session receipts: `intent`, `challengeId`, `channelId`, `acceptedCumulative`, `spent`, `units` and, for `open`, `topUp` and `close`, `txHash` are carried as extension fields of the `Receipt`, so its `Payment-Receipt` header parses as a `SessionReceipt`. `reference` is now the channel ID for every action; code that read the open or close transaction hash from `reference` should read `txHash` instead. `SessionReceipt::to_base_receipt` keeps the session fields as well. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Stripe server method ignoring `externalId`. A charge whose request carries an `externalId` now requires the credential payload to echo the same value and rejects it otherwise before creating the PaymentIntent, and the receipt carries the request's `externalId`. Clients must echo a request-bound `externalId`: mppx does, and `StripeProvider` does in releases after 0.14.0. PaymentIntent metadata values are now capped at Stripe's 500 characters, so a long client-supplied `source` can no longer make the request fail, and the method reuses one HTTP client instead of building one per verification. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `TempoProvider` signing for whatever chain a challenge named, which let a server move a client configured with a testnet RPC onto mainnet funds. An unpinned provider now pays only on the chain its RPC reports (one cached `eth_chainId` request on the first payment), signs on that chain when the challenge omits `chainId`, and rejects any other chain with `ChainIdMismatch`. Call `with_expected_chain_id` to pin the chain without the lookup, e.g. when the RPC is not reachable while signing. Tempo charges also fail fast when a challenge's `supportedModes` does not list `pull` instead of sending a transaction credential the server rejects, and the transaction's `validBefore` is capped at the challenge `expires`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Removed dependencies the library never used: `rand` (pulled in by `evm` and `utils`), `uuid` (pulled in by `tempo`, only used in tests) and `tokio-tungstenite` (pulled in by `ws`). The `sqlite` feature now enables `client`, where the SQLite channel store lives; before, `--features sqlite` alone compiled `rusqlite` without exposing the store.
- Migration: the implicit `rand` and `uuid` cargo features are gone. If you enabled `mpp/rand` or `mpp/uuid`, drop them; they did not change the public API. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed challenge fields being validated differently depending on how they arrived. Challenges parsed from `WWW-Authenticate`, challenges deserialized from JSON (MCP) and the challenge echoed in a credential now go through one validator: `intent` must match the intent grammar and is no longer lowercased by the header parser, `request` must be a base64url JSON object, `opaque` must be base64url, `digest` must be `sha-256=` followed by base64 (optionally wrapped in colons), and `expires` must be RFC 3339. `PaymentChallenge`'s `Deserialize` also rejects an empty `id` and a `header` other than `Payment-Authorization`. With these checks no bound field can contain the `|` that separates the fields in the challenge id input.
- Migration: `format_www_authenticate` refuses the same values, so a server using an intent name with characters other than letters, digits, `-` and `_`, or a `request` that is not a JSON object, has to change it. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))

### Patch Changes

- Fixed `accept_payment::parse` reading `Accept-Payment` weights loosely. The `q` parameter name is now matched case-insensitively, so `Q=0` is an opt-out instead of being ignored and treated as `q=1`. Values that are not HTTP qvalues (`.5`, `1e-1`, `+0.5`) and parameters without a value (`;q`) are rejected, and method tokens may contain the `:` and `_` that method names allow. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `FileStore::put` overwriting the key file in place, which let concurrent readers observe an empty or truncated value and could leave a corrupt file behind after a crash. The value is now written to a temp file and renamed over the key, so readers always see a complete value. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- `verify_credential_with_expected_request` and the other expected-request verifiers now reject a credential whose `externalId` differs from the expected request, so a payment issued for one order cannot settle another order of the same price. Callers that issue challenges with an `external_id` must pass the same value in the expected request. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `PaymentBodyLayer` reading credentials from `Authorization` only. It now reads the header selected by the verifier, so servers created with `requires_auth` can verify body-bound payments sent in `Payment-Authorization`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed body-bound payment front-ends buffering request bodies of any size before payment. The axum `MppChargeWithBody` extractor now honours `DefaultBodyLimit` (2 MiB unless configured), and the tower `PaymentBodyLayer` caps the body at 2 MiB, configurable with `max_body_bytes`. Oversized bodies are rejected with 413, and body read errors in `MppChargeWithBody` now return 400 instead of 500. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Parse challenge auth-param names case-insensitively, so `Realm=` or `ID=` are accepted and case-variant duplicates such as `id=` and `ID=` are rejected. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `Mpp::charge_challenge` and `Mpp::charge_challenge_with_options` issuing challenges without `chainId` on handlers built with `Mpp::create`, which the same handler then rejected with `credential chainId None does not match`. They now add the handler's chain ID like `charge()` does; a `chainId` already present in the request is kept. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Documented that `TempoChargeMethod::new` configures no replay store, and updated the advanced API examples to add one with `with_store`. Without a store, a hash or proof credential is accepted again until its challenge expires. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Exported `client::stripe::CreateTokenParams`, the argument of the `StripeProvider::new` callback, which could not be named before. Fixed the broken intra-doc links in the API docs. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `PaymentMiddleware` and `Fetch` answering the same 402 differently. The middleware now calls the provider's `prepare_http_payment_challenge` hook, reopens a stale session once after `410 Gone` instead of returning the 410, and returns a 402 that carries no challenge after a payment instead of failing. `Fetch` now repeats `Accept-Payment` on retries and sends requests whose body cannot be cloned, failing with `HttpError::CloneFailed` only when such a request is answered with a 402; a request builder that holds an error reports that error instead of `CloneFailed`. A session that is still gone after the retry is invalidated again rather than rolled back. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Added `mpp::client::PendingPayment`, the guard that commits, rolls back or abandons a created credential. It was only available as `mpp::mcp::client::PendingPayment`, which is now a re-export, and gained `new` and `invalidate`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Challenge and credential headers are now read by one tokenizer, so `parse_www_authenticate`, `parse_www_authenticate_all`, `extract_payment_scheme` and `PaymentProtocol::detect` agree on where a `Payment` scheme starts. An auth-param named `Payment` no longer splits a challenge in the list parser, `extract_payment_scheme` ignores text inside quoted-strings, empty list elements before a challenge are skipped by every parser, and only ASCII whitespace is skipped around the scheme. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the challenge parser rejecting a quoted `request` parameter of exactly 16384 bytes as too long. The limit is now the same for quoted and unquoted values, and the same as in mppx. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the proxy's OpenAPI discovery document describing paths clients cannot call. `generate_openapi` now prefixes paths with the configured `base_path`, writes `:param` route segments as `{param}` templates with matching path `parameters`, and emits `x-payment-info` in the multi-offer form (`{"offers": [...]}`) the discovery spec recommends instead of the flat single-offer shorthand. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `parse_www_authenticate` dropping an empty unquoted auth-param at the end of a header (`description=`). It is now kept as an empty value, as it already was when followed by a comma, and as mppx does. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `format_www_authenticate` emitting Latin-1 and control characters raw, which produced header values that clients could not read or that were not valid header values at all. Everything outside printable ASCII is now escaped as `\uXXXX`. Challenges that the parser would reject (empty `id`, invalid method name, `request` that is not base64url JSON) are refused, and `HttpTransport::respond_challenge` returns a 500 response instead of panicking or sending a bare `Payment` challenge when a challenge cannot be formatted. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Tempo fee payer co-signing sponsored transactions that spend its fee budget on work other than the charge. A sponsored transaction with an authorization list is now rejected, and an approve/swap prefix must approve exactly the swap's `maxAmountIn` and buy exactly the payment amount of the payment currency, matching mppx. Key authorizations stay sponsored by default; `ChargeMethod::with_fee_payer_allow_key_authorization(false)` rejects them. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `FileStore::put_if_absent` leaving an empty or truncated file behind when the write failed, which made the key look used forever. The value is now written to a temp file and hard-linked into place, so the key only exists once its contents are complete. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the build with `--no-default-features --features client,stripe`, which failed because `protocol::methods` was only compiled with `server` or `tempo`. The Stripe client types are now available with `stripe` alone. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `PaymentLayer::charge` and `PaymentBodyLayer::charge` being unusable from other crates: their return type named a private verifier type, and the layers were not `Clone` for non-`Clone` verifiers, so `axum::Router::layer` and `route_layer` rejected them. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Report errors that are not payment problems as the core spec's `internal-payment-error` with status 500, instead of the undefined `internal-error` type with status 402. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed clients dropping `WWW-Authenticate` values that contain non-ASCII bytes, so challenges from servers that send Latin-1 text raw (as mppx does) could not be paid. Received challenge headers are now decoded as ISO-8859-1 through the new `parse_www_authenticate_all_bytes`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed MCP payment errors to match the JSON-RPC transport spec and mppx: challenges are serialized with `request` as a native JSON object instead of a base64url string, verification failures use `-32043` (which `is_payment_required` now accepts), and one malformed challenge no longer discards the valid alternatives. `attach_credential` and `attach_receipt` no longer panic on non-object input; the new `try_attach_credential` and `try_attach_receipt` report the failure. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `PaymentMiddleware` sending the paid retry to the original request URL after a same-origin redirect. The credential now goes to the final URL that issued the challenge, matching `Fetch`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `MultiProvider` rejecting challenges for providers that send no `Accept-Payment` header, such as a Stripe-only offer failing with `NoSupportedChallenge` next to a Tempo session provider. `TempoProvider`, `TempoSessionProvider`, `TempoAccountsProvider` and `StripeProvider` now advertise the methods they support, and `MultiProvider` merges its children's headers, sending none if a child does not advertise. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed Tempo charge receipts for hash credentials echoing the transaction hash as the client spelled it. A hash sent in upper case or without the `0x` prefix was verified but returned unchanged as the receipt `reference`; the reference is now always the lower-case `0x`-prefixed hash, as it already was for transaction credentials. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed session channel IDs being matched as raw strings, so a credential that spelled the channel ID with uppercase hex was rejected with `channel-not-found`. The session method, the built-in channel stores and the SSE/WebSocket session helpers now key channels by the lowercase ID. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `Fetch` and `PaymentMiddleware` failing with `NoSupportedChallenge` when a paid request was answered with a 402 whose challenges the provider cannot pay. That response is now returned like a 402 without a challenge, as mppx does, so the caller can read its problem details. An unpayable first 402 is still an error. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Tempo session client trusting any escrow contract advertised by the server, which let a malicious server have the client approve and deposit into a contract of its choosing. Only the canonical escrow for the chain (or the one set with `with_escrow_contract`) is accepted now, and a challenge's `sessionProtocol` must match the escrow it is answered on. Use `TempoSessionProvider::with_allow_custom_escrow(true)` to accept server-chosen escrows, e.g. for local deployments. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the proxy helpers forwarding the client's `Payment-Authorization` credential to the upstream service; `scrub_request_headers` now strips it like `Authorization`. Fixed `ProxyConfig::match_route` letting a `:param` segment match `.`, `..` (also `%2e`-encoded) or a segment containing a backslash, which reached other upstream paths once the forwarding client normalised the URL, and `base_path` matching without a segment boundary (`/api` matched `/apiopenai/...`). (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- The prebuilt OpenAI proxy service now strips caller-supplied `OpenAI-Organization` and `OpenAI-Project` headers, and the Stripe service strips `Stripe-Context` in addition to `Stripe-Account`. A caller can no longer pick the organization, project or account the operator's key acts on. Headers set with `ServiceBuilder::header` are still sent. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `parse_www_authenticate_all` splitting challenges on `, Payment ` text inside quoted parameter values, which broke valid challenges and let a `Payment` challenge be read out of another scheme's quoted parameter. Scheme detection now also accepts a tab after `Payment`, auth-params accept whitespace around `=`, and a challenge's parameters end at the next auth scheme. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed realm auto-detection reading `HOST` and `HOSTNAME`. Container runtimes set these per replica, so each replica signed challenges with its own realm and rejected credentials for challenges issued by the others. The variable list now matches mppx (`MPP_REALM`, `FLY_APP_NAME`, `HEROKU_APP_NAME`, `RAILWAY_PUBLIC_DOMAIN`, `RENDER_EXTERNAL_HOSTNAME`, `VERCEL_URL`, `WEBSITE_HOSTNAME`). Deployments that relied on `HOSTNAME` now fall back to `"MPP Payment"` unless one of those is set; set `MPP_REALM` or call `.realm(...)` to keep the previous value. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the session server accepting voucher signatures the escrow contract cannot settle: high-s signatures and signatures with trailing bytes (such as the Tempo envelope magic trailer) are now rejected with `invalid-signature`. Vouchers must be a 65-byte `r || s || v` signature with `v` of 27 or 28, or a 64-byte EIP-2098 compact signature, and are stored in the 65-byte form. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the challenge `header` parameter accepting any HTTP field name, which let a server steer the client's credential into headers such as `Cookie` or `Proxy-Authorization`. Only `Payment-Authorization` is accepted now: challenges and credentials advertising any other field are rejected when parsed, clients no longer pay them, and `format_www_authenticate` refuses to emit them. `PaymentChallenge::with_header` and `with_secret_key_full` ignore other values. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the axum extractors and tower payment layers discarding why a credential was rejected. A credential that fails because of a server-side fault (RPC, store, upstream API) is now answered with `500` and no fresh challenge instead of `402` with one, so auto-paying clients no longer pay twice. The axum extractors answer every rejected credential with an `application/problem+json` body carrying the problem type and challenge id, returned as the new `MppChargeRejection::Problem` instead of `VerificationFailed`/`VerificationFailedOffers`. A challenge that cannot be sent as a header value is answered with `500` instead of an id-less `WWW-Authenticate: Payment`, and `500` responses no longer contain internal error text.
- Custom `ChargeChallenger` and `PaymentVerifier` implementations keep working and report every failure as `verification-failed`; implement the new `ChargeChallenger::verify_payment_for_route` and `PaymentVerifier::verify_credential` to report precise problems. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed session challenges advertising `feePayer: true` and a machine-token settlement route whenever the handler had fee sponsorship or machine tokens enabled for charges. The Tempo session method can honour neither, so every session open or top-up from a client that followed the advertisement failed. Session challenges now only advertise them when the session method opts in through the new `SessionMethod::supports_fee_payer` and `SessionMethod::supports_machine_tokens` hooks (both default to `false`); charge challenges are unchanged. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `sse::serve` and `ws_session` polling the application generator before looking at the channel, which started the first unit of work for channels that were exhausted, closed or missing. The generator is now first polled once the channel can pay for one tick: until then the stream asks for a voucher and waits, and it ends without polling the generator when the channel is closed or missing. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed session `close` settling for less than was spent when units were deducted while the close was in flight. The close amount is now re-checked against the current `spent` in the same atomic update that marks the channel `closing`, and a close that no longer covers it is rejected. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `TempoSessionProvider::close` forgetting the channel on any successful response. A `2xx` without a `Payment-Receipt` no longer removes the channel from memory and the channel store, so a close the server did not confirm can be retried instead of leaving a funded channel untracked. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed session `close` reporting success without settling on-chain. A close whose transaction reverted is no longer recorded as finalized, and a `SessionMethod` without a close signer now rejects `close` instead of finalizing the channel in the store only. A failed close also no longer leaves the channel stuck in `closing`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed session `close` rejecting a zero-amount close of a channel that was opened but never used, which left the deposit locked until a forced close. A funded channel with nothing spent and nothing settled on-chain can now be closed at `0`, refunding the payer. A close at or below a non-zero settled amount, or above the deposit, is still rejected. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Tempo session client forgetting an established channel whenever a voucher was answered without a receipt (any `402`, `5xx` or `429`), which opened a second channel on the next request and stranded the first deposit. `TempoSessionProvider::rollback_payment` now only discards a channel whose open was never accepted. A channel is forgotten when the server answers `410 Gone`, reported through the new `PaymentProvider::invalidate_payment` hook, which defaults to `rollback_payment`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `TempoSessionProvider` failing to open a channel on a legacy escrow contract with `native MPP channel is missing its descriptor`, a regression from 0.12.0. The failed open also left the channel tracked as open although it was never sent, so the next payment signed a voucher for a channel that does not exist. A failed open no longer leaves anything behind, and rolling back or invalidating a legacy channel no longer fails either. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `TempoSessionProvider` resuming a legacy channel suggested by the server without checking that the remaining deposit covers the request, which signed a voucher above the deposit, and panicking in debug builds when the settled amount plus the request amount overflowed. Such a channel is no longer resumed and a new one is opened instead. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `sse::serve` and `ws_session` polling forever when the channel is missing or the store fails. Only an insufficient balance now waits for a voucher; any other deduction error emits the final session receipt (if the channel is still readable) and stops. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `TempoSessionProvider::send_voucher` and `close` failing with `402` once the challenge of the last payment had expired, which is five minutes by default and shorter than many streams. Both now answer the fresh session challenge of a `402` response once, as top-ups already did. A challenge for a different payee, token, escrow or chain is refused. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Tempo session method overwriting its stored channel with an older on-chain read. A voucher that awaited the chain while the channel was closed stored `finalized: false` again and was accepted, and a lagging node or two top-ups finishing out of order lowered the recorded deposit so vouchers within the real deposit were rejected. `finalized` now stays set and the recorded deposit only grows. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `TempoSessionProvider::voucher_credential_with_top_up` and `voucher_credential_with_top_up_for_challenge` sizing the top-up from the deposit the server reports while checking the voucher against the provider's own, possibly older, deposit. After a top-up the provider did not make itself, a voucher within the real deposit failed with `voucher cumulative amount exceeds channel deposit`, and a needed top-up was too small. The larger of the two deposits is now used for both, and the local deposit is raised to it. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed session `open` accepting a channel that cannot pay for a single unit. The open transaction's deposit, and the channel's available balance once it is on-chain, must now cover the challenge `amount`; an open below it is rejected with `insufficient-balance` before the transaction is broadcast. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed a session `open` for a channel the server already records lowering the recorded deposit when its on-chain read was older than the record, e.g. from a lagging node right after a top-up. The deposit only grows, as it already did for vouchers and top-ups. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `TempoSessionProvider::pay` waiting forever when an earlier payment was never committed, rolled back or abandoned, as in the documented example. The wait for the payment lock now ends when the challenge expires and fails with `PaymentExpired`, and the example shows how to settle a credential before paying again. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `TempoSessionProvider::send_voucher` failing with `voucher cumulative amount exceeds channel deposit` when a `payment-need-voucher` event asked for more than the channel holds although `max_deposit` allowed a larger deposit. With `with_max_deposit` set it now tops the channel up first, as the spec requires and as `voucher_credential_with_top_up` already did, sized by `top_up_amount`, the server's `suggestedDeposit` and `max_deposit`. Without `max_deposit` the channel deposit stays the limit and the error is unchanged. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Serialize the session credential `settlementRoute` field in camelCase like every other payload field. The legacy `settlement_route` spelling is still accepted when parsing. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Tempo session method accepting a leading `+` in the `cumulativeAmount` and `additionalDeposit` of session credentials. These amounts must be ASCII digits only, like the challenge amounts. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `TempoSessionProvider::with_top_up_amount` being ignored whenever the server's `suggestedDeposit` was larger, so an automatic top-up deposited the server's amount instead of the configured one. The configured amount now takes precedence; a top-up still covers at least the shortfall and stays within `max_deposit`. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed Tempo session servers broadcasting client transactions before validating the credential. An `open` whose voucher has an invalid signature or exceeds the deposit is now rejected before its transaction is sent, instead of leaving a funded channel the server never recorded. A `topUp` transaction is now decoded and must be a Tempo transaction calling `topUp` on the escrow for the credential's channel and `additionalDeposit`; previously any signed transaction was relayed. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the `SignOptions` docs, which described defaults the Tempo charge client does not use: `nonce_key` defaults to `U256::MAX` (expiring nonce) rather than `U256::ZERO`, `nonce` to `0` rather than a fetched pending nonce, the gas fees to static values rather than the latest base fee, and `valid_before` applies to every charge. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Tempo fee payer broadcasting sponsored transactions without any pre-broadcast check when the node does not expose `tempo_simulateV1`, which includes the public `rpc.tempo.xyz` and `rpc.moderato.tempo.xyz` endpoints. The transaction's calls are now simulated with `eth_call` from the sender instead, so a transaction that would revert is rejected before the sponsor pays for it. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed SSE `message` events for values containing line breaks: the value was truncated at the first newline while still being charged, and streamed content could inject `payment-need-voucher` or `payment-receipt` events. `format_message_event` now emits one `data:` line per line, and `parse_event` accepts CRLF/CR line endings and `data:` fields without a space after the colon. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed amount parsing accepting forms the protocol does not allow, and the `u128` and `U256` parsers disagreeing about them. `ChargeRequest::parse_amount` and `SessionRequest::parse_amount` accepted a leading `+`, and `evm::parse_amount` (used by `amount_u256`, `parse_amount_u256` and split amounts) read `0x10` as 16, `1_000` as 1000 and the empty string as 0. All of them now accept ASCII digits only. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Stripe client not echoing a request-bound `externalId` in its credential, which made spec-compliant servers such as mppx reject the payment. The challenge's `externalId` now takes precedence over the one returned by `create_token`, and a challenge with a missing or empty `methodDetails.networkId` is rejected instead of passing an empty network ID to the callback. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Stripe charge method reporting a PaymentIntent in `requires_action` (e.g. 3D Secure) as `verification-failed`. It now fails with the new `ErrorCode::PaymentActionRequired`, which is reported as the `payment-action-required` problem like in mppx. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Stripe `ChargeMethod::verify` ignoring its `request` argument. It created the PaymentIntent from the request echoed by the credential, so a caller that used the method directly, or `Mpp::verify`/`Mpp::broadcast` with its own request, charged whatever amount and currency the credential named. The PaymentIntent amount, currency, metadata and `externalId` binding now come from the request passed in, as in mppx. `Mpp::stripe_verify_charge` and the other credential entry points pass the echoed request after checking it and behave as before. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Tempo charge method never checking `credential.source` on transaction (pull) credentials, so `ChargeValidation::source` reported whatever payer the client claimed. A `source` that is not a `did:pkh:eip155` DID for the challenge chain naming the recovered transaction sender is rejected now, before fee-payer co-signing and broadcast. When `source` is omitted, `ChargeValidation::source` reports the recovered sender. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed the Tempo charge server ignoring `methodDetails.supportedModes`: a credential whose mode the challenge does not advertise (a hash credential for a pull-only challenge, or a transaction credential for a push-only one) is now rejected. `ChargeOptions::supported_modes` values other than `"pull"`/`"push"` are rejected when the challenge is created. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed Tempo hash-credential verification counting the `Transfer` and `TransferWithMemo` logs of a single `transferWithMemo` call as two transfers, which let one transfer satisfy two expected transfers of a split payment. The pair is now matched as a single transfer. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed zero-amount Tempo proof challenges not being single-use: the replay marker was keyed by the proof signature, so a second account or a second signature could reuse the same challenge. The marker is now keyed by challenge id (`mpp:charge:proof:{id}`), as in mppx. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed Tempo charge verification accepting a payment when any matched transfer carried a memo bound to the challenge, even if another matched transfer carried an MPP attribution memo for a different challenge or server. Such conflicting attribution is now rejected, so one transaction cannot be credited to two challenges. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed `ws_session` looping on `needVoucher` forever once the channel is finalized or closing. It now emits the final session receipt and returns, matching the SSE session loop. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))
- Fixed in-band WebSocket vouchers being verified without telling the client the result, so a rejected voucher left the session waiting forever. The new `ws_session::process_vouchers` takes a sink for the socket and answers every credential frame with a `receipt` frame, or with an `error` frame after which it returns the verification error. `process_incoming_vouchers` is deprecated in its favour. (by @MatthiasSeitz, [#548](https://github.com/tempoxyz/mpp-rs/pull/548))

## 0.14.0 (2026-09-30)

### Minor Changes

- Offer OUSD first in Tempo server currency defaults. Servers on Tempo mainnet now accept OUSD, then USDC.e, and servers on Moderato accept OUSD, then pathUSD, issuing one charge challenge per accepted currency, whether or not fee sponsorship is enabled; omitted chains resolve from the configured RPC URL (mainnet by default), and unknown chains keep the single pathUSD default. Add an ordered `TempoBuilder::currencies` option that replaces the defaults (validated, deduplicated case-insensitively, and rejected when empty or combined with the now-deprecated single `currency` option), `Mpp::currencies`, `Mpp::charge*` helpers returning `Vec<PaymentChallenge>` (including for a single accepted currency), and multi-offer 402 responses in the Axum extractors and Tower layer. Credentials and session vouchers for any accepted currency verify, so existing channels opened in the previous default keep working.
- Decouple the sponsored fee token from the charge currency, matching mppx. A local fee payer pays gas in the configured `fee_payer_fee_token`, otherwise the first allowlisted fee token it holds a nonzero balance of, otherwise the first allowlisted token. The default fee-token allowlist is now pathUSD plus the chain's default currency (mainnet: pathUSD and USDC.e; Moderato: pathUSD), so sponsored OUSD charges pay gas in pathUSD or USDC.e. OUSD is not a default fee token.
- The built-in HTTP transport selects the first valid Payment offer across comma-joined or repeated WWW-Authenticate headers. (by @DerekCofausper, [#440](https://github.com/tempoxyz/mpp-rs/pull/440))

## 0.13.0 (2026-09-21)

### Minor Changes

- Remove custom primary Tempo charge memos from `TempoMethodDetails` and `TempoChargeExt`. Clients always generate attribution memos bound to the challenge and realm, and servers always verify that binding. Split-specific memos remain supported. (by @BrendanRyan, [#428](https://github.com/tempoxyz/mpp-rs/pull/428))

### Patch Changes

- Added a machine-payment metadata field to every Stripe PaymentIntent created by mpp-rs. (by @BrendanRyan, [#428](https://github.com/tempoxyz/mpp-rs/pull/428))
- Export session channel deduction helpers and update the multi-fetch example to
- atomically charge each request before releasing paid content. (by @BrendanRyan, [#428](https://github.com/tempoxyz/mpp-rs/pull/428))
- Enforce configured HTTP methods when matching paid proxy routes, preventing
- method-mismatched requests from reaching authenticated upstream services. (by @BrendanRyan, [#428](https://github.com/tempoxyz/mpp-rs/pull/428))
- Accept canonical payment method identifiers containing digits, colons, underscores, or hyphens after the initial lowercase letter. (by @BrendanRyan, [#428](https://github.com/tempoxyz/mpp-rs/pull/428))
- Reject a voucher when a concurrent request has already accepted the same or a
- higher cumulative authorization amount. (by @BrendanRyan, [#428](https://github.com/tempoxyz/mpp-rs/pull/428))
- Reject malformed human-readable amounts before converting them to base units,
- preventing inputs such as `.` from being normalized to zero. (by @BrendanRyan, [#428](https://github.com/tempoxyz/mpp-rs/pull/428))
- Added a `requires_auth` server option that advertises `header="Payment-Authorization"` so Payment credentials do not collide with ordinary `Authorization`. (by @BrendanRyan, [#428](https://github.com/tempoxyz/mpp-rs/pull/428))
- Preserve Unicode in challenge auth-params by encoding non-Latin-1 text as UTF-16 escapes and decoding those escapes while parsing. (by @BrendanRyan, [#428](https://github.com/tempoxyz/mpp-rs/pull/428))
- Reject payment transactions whose attribution memo is not bound to the active challenge before fee-payer signing or broadcast, preventing funds from settling before memo verification fails. (by @BrendanRyan, [#428](https://github.com/tempoxyz/mpp-rs/pull/428))

## 0.12.0 (2026-08-27)

### Minor Changes

- Accept asynchronous Alloy signers for Tempo fee sponsorship and session closing,
- enabling remote KMS, HSM, and MPC-backed server keys. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Added automatic native TIP-1034 channel top-ups before session vouchers exceed the current deposit, with credentials bound to each active WebSocket challenge across reconnects. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Support Tempo Wallet P-256 access keys for charge payments and expose the
- shared `store.json` loader for native command-line clients. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Add route-bound machineUSD session channels and atomic settlement into the
- merchant's configured stablecoin. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Add atomic stablecoin auto-swaps for native TIP-1034 session opens and top-ups,
- including the required Stablecoin DEX approval for charge and session payments. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Add a Charge-only payment provider backed by the canonical Tempo Accounts
- `store.json`, with lazy access-key selection and no separate signing mode. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Add separate non-mutating charge validation and terminal broadcast APIs, retaining verification as a compatibility alias and falling back to legacy method implementations. Add `TempoRelayConfig` and `TempoBuilder::relay` for delegating Tempo charge credential validation and finalization to Tempo API or a compatible MPP relay. Relay requests normalize the echoed challenge request, derive deterministic broadcast idempotency keys, validate returned receipts, and hide private relay failures. Add an Axum charge-relay example dogfooded against Tempo Moderato. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))

### Patch Changes

- Return a fresh body-bound payment challenge when request-body credential verification fails. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Pinned the Tempo dependency to the coordinated 7690815 revision. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Use the SDK-independent `mpp_` prefix for Stripe PaymentIntent idempotency keys. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Continue retrying distinct charge challenges within the configured payment
- retry limit, matching MPPx and allowing sponsored servers to rotate challenges
- that were rejected before settlement. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Match MPPx and Tempo fee sponsorship by encoding P-256 charge and TIP-1034 management credentials as sender-signed `0x78` envelopes. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Authorize canonical application WebSockets with their advertised opening amount,
- and provide a top-up-aware authorization path for full reusable channels. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Reject payment challenges containing malformed RFC 3339 `expires` timestamps during header parsing. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Pinned an updated Tempo dependency revision and reworked the one-time authorization test to sign the key authorization with a real root signer. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Preserve method-specific receipt fields when parsing and serializing payment receipts. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Mark successful body-bound payment responses as private while preserving existing
- `Cache-Control` directives, preventing shared caches from storing payment receipts. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Updated the pinned `tempo-alloy` git revision. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Only attach payment receipts to successful responses from Tower middleware and Axum handlers. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Reject payment challenges whose method identifier contains characters other
- than lowercase ASCII letters. Reject payment challenges reached through a
- cross-origin redirect before a credential can be created or sent. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Reject Payment challenges containing an unterminated quoted-string parameter. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Resolve persisted Tempo Wallet key authorizations against the Account Keychain before signing. Already-authorized access keys now omit the one-time authorization instead of failing fresh charge or session transactions with `KeyAlreadyExists`. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Send payment credential retries directly to the final same-origin response URL after redirects. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Use the bootstrapped Tempo localnet image for reproducible integration tests. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Allowed Tempo signature variants without primitive key metadata while safely rejecting unsupported proof signatures. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Update the Tempo SDK revision so fee-payer relays can select the transaction fee token. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))
- Load pending Accounts SDK key authorizations from the shared Tempo Wallet store so native Rust clients can provision a fresh access key with their first transaction. Open a fresh session after access-key rotation instead of trying to reuse a channel bound to the previous voucher signer. (by @BrendanRyan, [#399](https://github.com/tempoxyz/mpp-rs/pull/399))

## 0.11.0 (2026-07-16)

### Minor Changes

- Validate the credential `source` on the Tempo hash-credential verification path. The server now parses the `did:pkh:eip155` source before reserving the transaction hash, requires TIP-20 transfers to originate from the declared source address (falling back to the receipt sender when no source is provided), and rejects malformed or chain-mismatched sources with a uniform error. Adds `ChargeMethod::with_validate_sender` to authorize smart-account / relayer flows where the on-chain transfer sender differs from the declared source. (by @DerekCofausper, [#315](https://github.com/tempoxyz/mpp-rs/pull/315))
- Added a structured `reason: Option<PaymentFailureReason>` field to `PaymentFailedContext`, marked the struct `#[non_exhaustive]`, and added `PaymentFailedContext::new()` and `with_reason()` constructors. Downstream callers should construct it via `new()` and destructure it with `..` so future field additions remain non-breaking. (by @DerekCofausper, [#315](https://github.com/tempoxyz/mpp-rs/pull/315))
- Sponsored (fee-payer) charges now dry-run the co-signed transaction via `tempo_simulateV1` before broadcasting. If the transaction would revert on-chain, the sponsor rejects it instead of paying gas for a failing transaction. The check fails closed: if the simulation RPC is unavailable, the charge is rejected. (by @DerekCofausper, [#315](https://github.com/tempoxyz/mpp-rs/pull/315))
- Added TIP-1034 Tempo session client primitives for descriptor-backed channels, precompile ABI helpers, voucher signing, and fee-sponsored session opens. (by @DerekCofausper, [#315](https://github.com/tempoxyz/mpp-rs/pull/315))

### Patch Changes

- Added configurable incremental 402 challenge retries for HTTP clients. (by @DerekCofausper, [#315](https://github.com/tempoxyz/mpp-rs/pull/315))
- Rejected oversized `WWW-Authenticate` `request` parameters before decoding payment challenges. (by @DerekCofausper, [#315](https://github.com/tempoxyz/mpp-rs/pull/315))
- Updated README documentation with an expanded protocol description, added an MPP SDKs table listing official implementations in multiple languages, and cleaned up URLs and prose throughout. (by @DerekCofausper, [#315](https://github.com/tempoxyz/mpp-rs/pull/315))
- Add client-side Tempo chain pinning. `TempoProvider::with_expected_chain_id` rejects charge challenges whose `methodDetails.chainId` conflicts with the configured chain ID, and signs on the pinned chain when the challenge omits it — matching the mpp-go conformance ABI. (by @DerekCofausper, [#315](https://github.com/tempoxyz/mpp-rs/pull/315))
- Align Tempo zero-amount proof shape with the wallet proof flow. (by @DerekCofausper, [#315](https://github.com/tempoxyz/mpp-rs/pull/315))

## 0.2.0 (2026-07-16)

## 0.3.0 (2026-07-16)

## 0.1.4 (2026-06-02)

## 0.10.4 (2026-06-02)

### Patch Changes

- Bumped Tempo dependencies to v1.8.0 for T5 compatibility. (by @Mablr, [#263](https://github.com/tempoxyz/mpp-rs/pull/263))
- Hardened payment validation for expired challenges, body digest checks, and Tempo charge verification. (by @Mablr, [#263](https://github.com/tempoxyz/mpp-rs/pull/263))

## 0.2.4 (2026-06-02)

## 0.1.3 (2026-05-18)

## 0.10.3 (2026-05-18)

### Patch Changes

- Added payment event lifecycle hooks (by @BrendanRyan, [#257](https://github.com/tempoxyz/mpp-rs/pull/257))

## 0.2.3 (2026-05-18)

## 0.1.2 (2026-05-13)

## 0.10.2 (2026-05-13)

### Patch Changes

- Scoped Tempo session voucher and close operations to the active challenge's channel so client-managed channels cannot be mixed across sessions. (by @github-actions[bot], [#255](https://github.com/tempoxyz/mpp-rs/pull/255))

## 0.2.2 (2026-05-13)

## 0.1.1 (2026-05-13)

## 0.10.1 (2026-05-13)

### Patch Changes

- Validated challenge-bound memos for server-broadcast Tempo charge transactions. (by @BrendanRyan, [#247](https://github.com/tempoxyz/mpp-rs/pull/247))
- Validated fee-sponsored approval targets against the swap input token. (by @BrendanRyan, [#247](https://github.com/tempoxyz/mpp-rs/pull/247))
- Bound zero-amount Tempo proof signatures to the wallet being authenticated. (by @BrendanRyan, [#247](https://github.com/tempoxyz/mpp-rs/pull/247))
- Locked Tempo session channels locally while close settlement is in progress. (by @BrendanRyan, [#247](https://github.com/tempoxyz/mpp-rs/pull/247))
- Refreshed on-chain Tempo session channel state before accepting vouchers. (by @BrendanRyan, [#247](https://github.com/tempoxyz/mpp-rs/pull/247))
- Rejected replayed Tempo session vouchers that do not increase the accepted cumulative amount. (by @BrendanRyan, [#247](https://github.com/tempoxyz/mpp-rs/pull/247))
- Preserved fresh channel deposit state when accepting higher Tempo session vouchers. (by @BrendanRyan, [#247](https://github.com/tempoxyz/mpp-rs/pull/247))
- Stopped WebSocket reconnect retries after a payment credential is sent without a receipt. (by @BrendanRyan, [#247](https://github.com/tempoxyz/mpp-rs/pull/247))

## 0.2.1 (2026-05-13)

### Patch Changes

- Made the `axum` extractor use route-aware expected-request verification by default. High-level `MppCharge` extraction now forwards the route amount into verification so built-in Tempo and Stripe challengers compare incoming credentials against the route's expected charge request instead of trusting the echoed request alone. (by @BrendanRyan, [#213](https://github.com/tempoxyz/mpp-rs/pull/213))

## 0.10.0 (2026-04-20)

### Minor Changes

- Added `ChargeMethod::with_fee_payer_policy_override()` for per-server tuning of the fee-sponsor policy (`max_gas`, `max_fee_per_gas`, `max_priority_fee_per_gas`, `max_total_fee`, `max_validity_window_seconds`), with per-chain defaults matching mppx#342. (by @stevencartavia, [#211](https://github.com/tempoxyz/mpp-rs/pull/211))

## 0.2.0 (2026-04-20)

## 0.1.1 (2026-04-10)

## 0.9.3 (2026-04-10)

### Patch Changes

- Fixed `credential.source` DID mismatch between $0 proofs and paid charges in Keychain signing mode. The proof path now uses the wallet address (matching mppx and the paid charge path). Server-side `verify_proof` falls back to an on-chain keychain lookup when the recovered signer differs from the source address. (by @BrendanRyan, [#209](https://github.com/tempoxyz/mpp-rs/pull/209))

## 0.9.2 (2026-04-08)

### Patch Changes

- Cache chain ID in `ChargeMethod` to avoid a redundant `eth_getChainId` RPC call (~270ms) on every `verify()` invocation. The chain ID is fetched once on the first call and reused for all subsequent verifications. (by @BrendanRyan, [#198](https://github.com/tempoxyz/mpp-rs/pull/198))
- Use `eth_sendRawTransactionSync` (EIP-7966) instead of `eth_sendRawTransaction` + polling for receipt. The Tempo node returns the full receipt in a single blocking call, eliminating the client-side polling loop and reducing broadcast latency from 0.5–7.5s to ~500ms. (by @BrendanRyan, [#198](https://github.com/tempoxyz/mpp-rs/pull/198))

## 0.9.1 (2026-04-07)

### Patch Changes

- Enforced fail-closed behavior for the `expires` field in `verify_hmac_and_expiry`. Credentials missing the `expires` field are now rejected with a `CredentialMismatch` error instead of being silently accepted. Session challenges now include a default expiry. (by @EvanChipman, [#194](https://github.com/tempoxyz/mpp-rs/pull/194))
- Fixed busy loop in `serve()` caused by default `wait_for_update()` returning immediately instead of pending. (by @EvanChipman, [#194](https://github.com/tempoxyz/mpp-rs/pull/194))
- Fixed `split_payment_challenges` to handle leading whitespace in header values. Added tests for merged comma-separated challenges and quoted `"Payment"` boundaries. (by @stevencartavia, [#170](https://github.com/tempoxyz/mpp-rs/pull/170))

## 0.9.0 (2026-04-07)

### Minor Changes

- Added zero-amount proof credential support for identity flows. Introduced a new `PayloadType::Proof` variant with EIP-712 signing via a new `proof` module, enabling clients to authenticate without sending a blockchain transaction. Updated `TempoCharge`, `TempoProvider`, and server-side verification to handle zero-amount challenges with signed proofs. (by @BrendanRyan, [#182](https://github.com/tempoxyz/mpp-rs/pull/182))

## 0.8.4 (2026-04-02)

### Patch Changes

- Bind payee and currency validation to all session actions (open, voucher, close, topUp). (by @horsefacts, [#188](https://github.com/tempoxyz/mpp-rs/pull/188))

## 0.8.3 (2026-03-31)

### Minor Changes

- Client now matches challenges by `provider.supports(method, intent)` instead of assuming a single challenge, mirroring the mppx TypeScript SDK. Both `PaymentExt` (fetch) and `PaymentMiddleware` parse all challenges and select the first one the provider supports. (by @grandizzy, [#185](https://github.com/tempoxyz/mpp-rs/pull/185))
- Added `HttpError::NoSupportedChallenge` variant for when a 402 response contains no challenge matching the provider's supported methods. (by @grandizzy, [#185](https://github.com/tempoxyz/mpp-rs/pull/185))

### Patch Changes

- Added split payments support to Tempo charge verification and transaction building. Extended `TempoCharge` and `TempoChargeExt` to parse and propagate split recipients from `methodDetails`, and refactored transfer call construction and verification to handle multiple transfers using order-insensitive matching. (by @BrendanRyan, [#187](https://github.com/tempoxyz/mpp-rs/pull/187))

## 0.8.2 (2026-03-31)

### Patch Changes

- Fixed a timing side-channel in HMAC challenge ID verification by replacing non-constant-time string comparison with `constant_time_eq`. Added an `ast-grep` lint rule to prevent future regressions. (by @BrendanRyan, [#175](https://github.com/tempoxyz/mpp-rs/pull/175))

## 0.8.1 (2026-03-30)

### Patch Changes

- Fixed a race condition in `ChannelStoreAdapter` where concurrent `update_channel` calls for the same channel could overwrite each other. Added per-channel async mutex locking to serialize read-modify-write operations within a single process, along with tests reproducing the original race. (by @BrendanRyan, [#177](https://github.com/tempoxyz/mpp-rs/pull/177))

## 0.8.0 (2026-03-26)

### Minor Changes

- Added a Stripe Shared Payment Token (SPT) example demonstrating the full 402 → challenge → credential → retry flow using Stripe's payment method. Includes a server with SPT proxy endpoint and a headless client using a test card. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))
- Added `fee_payer()` and `chain_id()` getters to `Mpp`. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))
- Added Stripe payment method support (`method="stripe"`, `intent="charge"`) with client-side `StripeProvider` for SPT creation, server-side `ChargeMethod` for PaymentIntent verification, and `Mpp::create_stripe()` builder integration. Added `stripe` and `integration-stripe` feature flags backed by `reqwest`. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))

### Patch Changes

- Fixed multiple payment bypass and griefing vulnerabilities (GHSA-fxc9-7j2w-vx54). (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))
- Bumped `alloy` dependency from 1.7 to 1.8 and `tempo-alloy`/`tempo-primitives` from 1 to 1.5 across the main crate and all examples. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))
- Disabled tempo lint PR comments while keeping the lint CI check enforced. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))
- Fixed `base64url_decode` to accept standard base64 (`+`, `/`, `=` padding) in addition to URL-safe base64, following Postel's law and aligning with the mppx TypeScript SDK behavior. Added tests covering standard base64 with padding, URL-safe without padding, and standard alphabet without padding in both `types.rs` and `headers.rs`. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))

## 0.7.0 (2026-03-23)

### Minor Changes

- Refactored Tempo client to use `tempo_alloy` types instead of local duplicates. Removed the local `abi.rs` module and replaced local ABI definitions (`ITIP20`, `IStablecoinDEX`, `IAccountKeychain`) with imports from `tempo_alloy::contracts::precompiles`. Simplified gas estimation to use the provider's `estimate_gas` method via `TempoTransactionRequest` instead of manual JSON-RPC construction. (by @BrendanRyan, [#143](https://github.com/tempoxyz/mpp-rs/pull/143))

## 0.6.0 (2026-03-22)

### Minor Changes

- Migrated tempo dependencies (`tempo-alloy`, `tempo-primitives`) from git dependencies to crates.io versioned dependencies, and added `cargo publish` to the release workflow with registry token support. (by @BrendanRyan, [#142](https://github.com/tempoxyz/mpp-rs/pull/142))

### Patch Changes

- Fixed core problem type base URI to use the canonical `https://paymentauth.org/problems` domain instead of the temporary GitHub Pages URL. (by @BrendanRyan, [#142](https://github.com/tempoxyz/mpp-rs/pull/142))

## `mpp@0.5.0`

### Minor Changes

- Added fee payer support to the Tempo payment provider. The client now builds 0x76 transactions with expiring nonces and a placeholder fee payer signature, and the server co-signs them by recovering the sender, setting the fee token, and re-encoding as a standard 0x76 transaction with both signatures. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added comprehensive integration and unit test coverage across client fetch, client middleware, MCP payment roundtrip, server middleware, server HMAC challenge verification, and SSE metered streaming flows. Also added a `feature-matrix` CI job to validate all feature flag combinations, and introduced `Mpp::new_with_config` test helper and made `detect_realm` pub(crate). (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added network-specific default currencies for Tempo, defaulting to USDC (USDC.e) on mainnet and pathUSD on testnet. Deprecated the `DEFAULT_CURRENCY` constant in favor of `DEFAULT_CURRENCY_MAINNET` and `DEFAULT_CURRENCY_TESTNET`. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added `TempoCharge` builder API (`from_challenge() → sign() → into_credential()`), gas resolution (`resolve_gas()` and `resolve_gas_with_stuck_detection()` for mempool stuck-tx replacement), `SignOptions` for overriding nonce/gas/signing parameters, and `TempoClientError` with `classify_rpc_error()` for structured error classification. Moved `abi.rs` from `protocol::methods::tempo` to `client::tempo` and consolidated the `ITIP20` sol! definition. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added end-to-end support for the `0x78` fee payer envelope format, enabling clients to request gas sponsorship by sending a `0x78 || RLP(...)` encoded transaction that servers co-sign and broadcast as a standard `0x76` Tempo transaction. Extended server-side verification to accept both `0x76` and `0x78` transaction types, added `sign_and_encode_fee_payer_envelope` signing helpers, and added integration tests asserting on-chain fee payer and sender addresses. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added integration tests for the MPP charge flow against a live Tempo blockchain. Introduced an `integration` feature flag, updated dev dependencies (`axum`, `reqwest`, `hex`, tokio `net` feature), added a `test-integration` Makefile target, and added `tests/integration_charge.rs` with E2E tests covering health checks, 402 challenge flow, full charge round-trips, and auth scheme validation. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))

### Patch Changes

- Added comprehensive test coverage for session provider, channel store, and session verification logic. Tests cover voucher sending edge cases, channel state management, HMAC validation, and `SessionVerifyResult` debug formatting. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Auto-detect `realm` from environment variables in `Mpp::create()`. Checks `MPP_REALM`, `FLY_APP_NAME`, `HEROKU_APP_NAME`, `HOST`, `HOSTNAME`, `RAILWAY_PUBLIC_DOMAIN`, `RENDER_EXTERNAL_HOSTNAME`, `VERCEL_URL`, `WEBSITE_HOSTNAME` in order, falling back to `"MPP Payment"`. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Updated URLs from `machinepayments.dev` to `mpp.dev` in README and removed "web3" keyword from Cargo.toml metadata. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added auto-detection of `realm` from environment variables in `Mpp::create()`. Checks `MPP_REALM`, `FLY_APP_NAME`, `HEROKU_APP_NAME`, `HOST`, `HOSTNAME`, `RAILWAY_PUBLIC_DOMAIN`, `RENDER_EXTERNAL_HOSTNAME`, `VERCEL_URL`, and `WEBSITE_HOSTNAME` in order, falling back to `"MPP Payment"`. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Introduced `TempoClientError` enum scoped under `client::tempo` for typed Tempo-specific client errors (AccessKeyNotProvisioned, SpendingLimitExceeded, InsufficientBalance, TransactionReverted). Added `MppError::Tempo` variant gated on `client + tempo` features with `classify_rpc_error` to parse RPC error messages into typed variants, replacing brittle string matching in downstream consumers. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added `TempoSigningMode` enum (Direct/Keychain) and centralized transaction helpers for client-side Tempo payments. New `client::signing` module provides `sign_and_encode` / `sign_and_encode_async` with keychain envelope support. New `client::tx_builder` module provides `TempoTxOptions`, `build_tempo_tx`, `estimate_gas`, `build_estimate_gas_request`, and `build_charge_credential`. Updated `TempoProvider`, `TempoSessionProvider`, and `create_open_payload` to use the new signing mode abstraction, eliminating duplicated transaction construction logic across consumers. Fixed potential `u64` overflow in `parse_gas_estimate` by using `checked_add`. Added 46 new unit tests (432 → 478) covering signature variant correctness, encoding boundary conditions, escrow resolution priority, deposit edge cases, re-export verification, and gas estimate overflow protection. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added client and protocol helpers upstreamed from presto:
- `PaymentChallenge::is_expired()` and `expires_at()` for RFC 3339 challenge expiry checks
- `TempoNetwork` enum with `from_chain_id()`, `default_rpc_url()`, and `default_currency()` lookups
- `client::tempo::keychain` module with `query_key_spending_limit()` and `local_key_spending_limit()` for Tempo access key spending limit queries
- ABI encoding helpers (`encode_transfer`, `encode_approve`, `encode_swap_exact_amount_out`, `DEX_ADDRESS`) in `protocol::methods::tempo::abi`
- `PaymentChallenge::validate_for_charge()` and `validate_for_session()` for common challenge validation
- `network()` convenience methods on `TempoChargeExt` and `TempoSessionExt`
- `parse_memo_bytes()` utility for hex memo string to 32-byte array conversion
- `extract_tx_hash()` utility for extracting transaction hashes from base64url receipts (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))

## `mpp@0.4.0`

### Minor Changes

- Added Axum middleware support with extractors and response types, updated library description to "402 Protocol", and made SSE stream pluggable by returning a `Stream` instead of `Receiver`. (by @BrendanRyan, [#59](https://github.com/tempoxyz/mpp-rs/pull/59))

### Patch Changes

- Fixed parameter parsing to reject duplicate parameters, empty challenge IDs, and non-ISO8601 timestamp formats in conformance with protocol strictness requirements. (by @BrendanRyan, [#59](https://github.com/tempoxyz/mpp-rs/pull/59))

## `mpp@0.3.0`

### Minor Changes

- Simplified server API with dollar amounts and smart defaults. Added `Mpp::create()` and `mpp.charge("1")` for one-line payment setup.
- Added default 5-minute expiration for challenges and `prepare_request` hook for request customization.
- Aligned Rust SDK with mppx TypeScript SDK for cross-language consistency.
- Removed failed receipt state — server now returns 402 for payment failures per IETF spec.
- Fixed tempo payment method to match TypeScript SDK behavior. Fixed 402 responses for failed receipts per spec.
- Updated `rand` dependency from 0.8 to 0.9. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))

### Patch Changes

- Mandated JCS (RFC 8785) for canonical JSON serialization of request parameters by replacing `serde_json::to_string` with `serde_json_canonicalizer::to_string` throughout the protocol layer. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))
- Updated currency address from AlphaUSD to PathUSD across all examples, documentation, and tests. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))
- Normalized error codes to kebab-case format per IETF spec update (§8.2). (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))
- Updated documentation URL and optimized CI workflows. Added GitHub Pages documentation deployment, switched to cargo-hack for feature testing, and pinned release workflow to commit SHA. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))
