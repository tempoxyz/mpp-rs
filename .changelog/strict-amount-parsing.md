---
mpp: patch
---

Fixed amount parsing accepting forms the protocol does not allow, and the `u128` and `U256` parsers disagreeing about them. `ChargeRequest::parse_amount` and `SessionRequest::parse_amount` accepted a leading `+`, and `evm::parse_amount` (used by `amount_u256`, `parse_amount_u256` and split amounts) read `0x10` as 16, `1_000` as 1000 and the empty string as 0. All of them now accept ASCII digits only.
