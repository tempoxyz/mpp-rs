# Basic

A barebones example demonstrating a payment-gated Fortune Teller API using the Machine Payment Protocol.

The server exposes two endpoints:

- `GET /api/health` — Free, returns `{"status": "ok"}`
- `GET /api/fortune` — Costs $1.00 in pathUSD, returns a random fortune with a payment receipt

## Running

### 1. Start the server

```bash
cd examples/basic
cargo run --bin basic-server
```

The server listens on `http://localhost:3000`. A random merchant address is generated on startup.

### 2. Run the client

In another terminal:

```bash
cd examples/basic
cargo run --bin basic-client
```

The client automatically handles the 402 Payment Required flow: it receives a payment challenge, signs a transaction, and retries with the credential.

A random wallet is generated on startup (or set `PRIVATE_KEY=0x...`).

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PRIVATE_KEY` | Random | Client's private key (hex, with or without `0x` prefix) |
| `BASE_URL` | `http://localhost:3000` | Client's base URL for the server |
| `RPC_URL` | `https://rpc.moderato.tempo.xyz` | Tempo RPC endpoint |
