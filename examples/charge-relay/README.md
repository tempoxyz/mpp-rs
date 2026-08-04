# Axum Charge Relay

A small Axum API that accepts pathUSD on Tempo Moderato. The server issues MPP
charges locally, then delegates credential validation and finalization to Tempo
API's MPP relay.

## Setup

Create a Tempo API key with the `mpp:write` scope and provide it only to the
server process:

```bash
export TEMPO_API_KEY=tempo:sk:...
export TEMPO_API_URL=https://api.tempo.xyz
export MPP_SECRET_KEY=$(openssl rand -base64 32)
cargo run -p charge-relay-example --bin charge-relay-server
```

`TEMPO_API_URL` may target a compatible self-hosted or preview Tempo API.
`MPP_SECRET_KEY` has a development-only default for local use.

In another terminal, run the basic MPP client against the paid photo route:

```bash
cargo run -p basic-example --bin basic-client -- http://localhost:5173/api/photo
```

The flow is:

1. The server returns a `tempo/charge` challenge for pathUSD.
2. The payer signs a Tempo transaction and returns the MPP credential.
3. The adapter calls `POST /v1/mpp/validate`, then `POST /v1/mpp/broadcast`.
4. The relay receipt becomes the `Payment-Receipt` response header.

The handler uses `Mpp::broadcast_credential`, which re-validates before the
terminal relay call. `Mpp::validate_credential` is also available for advisory,
non-mutating pre-checks; `verify_credential` remains a compatibility alias for
the broadcast path.

The relay broadcasts pull credentials. For push credentials, it recognizes the
already-broadcast transaction and returns its receipt without sending it again.
Relay failures are converted to payment failures without exposing API keys,
private relay messages, or relay URLs.
