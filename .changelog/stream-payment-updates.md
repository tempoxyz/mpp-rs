---
mpp: minor
---

`TempoSessionProvider::stream_event` records the `spent` of each `payment-receipt` event that a streaming response carries. Servers send these events when they charge a request while its output is delivered or settle it at its final usage. When `spent` changed, the provider adds the change to its spend ledger, so `spend()` follows the stream, and emits the new `ClientEvent::PaymentUpdate` (`payment.update`, `PaymentUpdateContext` with the URL, channel, new `spent` and signed change). `ClientEvents::on_payment_update` subscribes to it.
