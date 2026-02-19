---
mpp: minor
---

Added `TempoSigningMode` enum (Direct/Keychain) and centralized transaction helpers for client-side Tempo payments. New `client::signing` module provides `sign_and_encode` / `sign_and_encode_async` with keychain envelope support. New `client::tx_builder` module provides `TempoTxOptions`, `build_tempo_tx`, `estimate_gas`, `build_estimate_gas_request`, and `build_charge_credential`. Updated `TempoProvider`, `TempoSessionProvider`, and `create_open_payload` to use the new signing mode abstraction, eliminating duplicated transaction construction logic across consumers.
