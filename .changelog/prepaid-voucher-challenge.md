---
mpp: patch
---

Fixed a prepaid session request failing with "no challenge available for voucher" when its metered stream asked for another voucher: `TempoSessionProvider::prepaid_credential` now keeps the Challenge it signed for, as a paid `402` does, so `payment-need-voucher` is answered against it. A channel restored and primed from a session snapshot paid its first request this way, so streamed replies on Tempo's Anthropic proxy failed on every run after the first.
