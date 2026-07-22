# MPP service catalog client

Calls an arbitrary HTTP endpoint from the [MPP service catalog](https://mpp.dev/services).
The client selects a payment provider from the server's `402 Payment Required`
challenge, so it does not contain service-specific adapters.

Tempo `charge` and `session` challenges use the active account and P-256 access
key from Tempo Wallet's `~/.tempo/wallet/store.json`. Session channels persist
in the MPPx-compatible `~/.tempo/wallet/channels.db`, scoped to the target
service origin. A cold process can therefore continue an existing channel.

```bash
cargo run -p catalog-client-example -- \
  GET 'https://stabletravel.dev/api/reference/locations?keyword=SFO&subType=AIRPORT%2CCITY'

cargo run -p catalog-client-example -- \
  POST https://rpc.mpp.tempo.xyz/ \
  '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
```

The optional third positional argument is sent as JSON when it parses as JSON,
or as a raw request body otherwise. Pass `-` to read raw bytes from stdin or
`@PATH` to read them from a file. Set `MPP_REQUEST_HEADERS` to a JSON object for
application-specific headers and content types. Together these cover the
catalog's JSON, form, file, and authenticated application requests without
service-specific payment adapters.

Configuration:

- `TEMPO_RPC_URL`: overrides the RPC selected from the wallet's active chain.
- `MPP_CHANNEL_STORE`: overrides the shared channel database path.
- `MPP_DEFAULT_DEPOSIT`: initial session deposit, default `20000` atomic units.
- `MPP_MAX_DEPOSIT`: local session spending ceiling, default `1000000` atomic units.
- `MPP_REQUEST_HEADERS`: JSON object of headers attached to the application request.
- `STRIPE_SPT_ENDPOINT`: optional application endpoint that accepts the
  `CreateTokenParams` JSON and returns `{ "spt": "...", "externalId": "..." }`.
  This enables Stripe-only catalog services while leaving card authorization
  and SPT issuance in the embedding application.

This example pays real challenges. Inspect the target service's catalog price
before running it.
