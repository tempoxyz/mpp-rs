---
mpp: patch
---

Added client and protocol helpers upstreamed from presto:
- `PaymentChallenge::is_expired()` and `expires_at()` for RFC 3339 challenge expiry checks
- `TempoNetwork` enum with `from_chain_id()`, `default_rpc_url()`, and `default_currency()` lookups
- `client::tempo::keychain` module with `query_key_spending_limit()` and `local_key_spending_limit()` for Tempo access key spending limit queries
- ABI encoding helpers (`encode_transfer`, `encode_approve`, `encode_swap_exact_amount_out`, `DEX_ADDRESS`) in `protocol::methods::tempo::abi`
- `PaymentChallenge::validate_for_charge()` and `validate_for_session()` for common challenge validation
- `network()` convenience methods on `TempoChargeExt` and `TempoSessionExt`
- `parse_memo_bytes()` utility for hex memo string to 32-byte array conversion
- `extract_tx_hash()` utility for extracting transaction hashes from base64url receipts
