---
mpp: minor
---

Report what payments cost and where money moves, so clients can show spending without tracking channels themselves:

- `PaymentResponseContext::amount` is what the server charged for the request: a charge's amount, or for a session the change in the channel's `spent` from the receipt. Providers report session costs through the new `PaymentProvider::record_receipt`, which defaults to `observe_receipt` and no amount.
- A new `channel.deposit` event (`ClientEvent::Deposit`, `ClientEvents::on_deposit`) reports when the server accepts a session channel's open or a top-up, including background top-ups, with the URL, channel, token, amount added and resulting deposit. Enable it with `TempoSessionProvider::with_events` or `TempoAccountsProvider::with_session_events`.
- `PaymentProvider::stream_event` lets a provider answer payment events in a response stream; `TempoSessionProvider` and `TempoAccountsProvider` answer mppx `payment-need-voucher` and `payment-receipt`. `ForwardProxy` uses it for paid `text/event-stream` responses, so a session stream that asks for more vouchers keeps flowing to a client that knows nothing about MPP.
