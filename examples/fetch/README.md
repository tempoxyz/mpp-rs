# fetch

CLI tool for fetching URLs with automatic payment handling.

## Build

```bash
cd examples/fetch
cargo build --release
```

## Usage

```bash
# GET request
fetch https://api.example.com/resource

# POST with body
fetch -X POST -d '{"query": "test"}' https://api.example.com/search

# PUT request
fetch -X PUT -d '{"name": "updated"}' https://api.example.com/resource/123

# DELETE request
fetch -X DELETE https://api.example.com/resource/123
```

## Credentials

Provide credentials via flags:

```bash
fetch --key 0x... --rpc-url https://rpc.testnet.tempo.xyz/ https://api.example.com
```

Or via environment variables:

```bash
export TEMPO_PRIVATE_KEY=0x...
export TEMPO_RPC_URL=https://rpc.testnet.tempo.xyz/  # optional, this is the default
fetch https://api.example.com/resource
```

## How It Works

When a request returns `402 Payment Required`:

1. The client parses the `WWW-Authenticate` header to get the payment challenge
2. Creates a credential by executing the payment on Tempo
3. Retries the request with the `Authorization` header

This happens automatically via the mpay `Fetch` extension trait.

## Testing with the server example

1. Start the server:
   ```bash
   cd ../server
   MERCHANT_ADDRESS=0x... cargo run --release
   ```

2. Test the free endpoint:
   ```bash
   curl http://localhost:3000/free
   ```

3. Test the paid endpoint with fetch:
   ```bash
   TEMPO_PRIVATE_KEY=0x... ./target/release/fetch http://localhost:3000/paid
   ```
