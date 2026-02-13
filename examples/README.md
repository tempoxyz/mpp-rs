# Examples

## Inline Examples

Run directly from the crate root:

| Example | Description | Command |
|---------|-------------|---------|
| `parse_headers` | Core protocol parsing & formatting round-trip | `cargo run --example parse_headers` |
| `basic_server` | Payment-gated fortune teller (server flow) | `MERCHANT_ADDRESS=0x... cargo run --example basic_server --features "tempo,server"` |
| `fetch_client` | Fetch a URL with automatic 402 payment | `TEMPO_PRIVATE_KEY=0x... cargo run --example fetch_client --features "tempo,client" -- <URL>` |

## Standalone Examples

These are separate crates with their own dependencies (e.g., axum, clap):

| Example | Description |
|---------|-------------|
| [server/](./server/) | Full axum server with payment-gated endpoints |
| [fetch/](./fetch/) | Full CLI tool for fetching URLs with payment handling |
