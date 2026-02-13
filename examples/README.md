# mpay Examples

Standalone, runnable examples demonstrating the mpay HTTP 402 payment flow.

## Examples

| Example | Description |
|---------|-------------|
| [basic](./basic/) | Payment-gated Fortune Teller API |
| [session/multi-fetch](./session/multi-fetch/) | Multiple paid requests over a single payment channel |
| [session/sse](./session/sse/) | Pay-per-token LLM streaming with SSE |

## Running Examples

Each example is a standalone Cargo crate with a server and client binary.

```bash
# Basic example
cd examples/basic
cargo run --bin basic-server   # Terminal 1
cargo run --bin basic-client   # Terminal 2

# Session multi-fetch
cd examples/session/multi-fetch
cargo run --bin session-server   # Terminal 1
cargo run --bin session-client   # Terminal 2

# Session SSE streaming
cd examples/session/sse
cargo run --bin sse-server   # Terminal 1
cargo run --bin sse-client   # Terminal 2
```
