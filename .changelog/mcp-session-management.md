---
mpp: minor
---

Session channels can be topped up and closed over MCP. A `ManagementTransport` delivers a management credential to the resource that issued its challenge, and `PaymentProvider::pay_with_management` pays a challenge with any top-up the payment needs sent through it instead of HTTP. It defaults to `pay_with_context`; `TempoSessionProvider`, `TempoAccountsProvider` and `MultiProvider` implement it. `TempoSessionProvider::close_with` closes a channel through a transport.

`mcp::client::McpManagement` is the MCP transport: it repeats a tool call with the credential in `_meta`, as mppx's MCP server and Mercator accept top-ups and closes, and returns the receipt of the server's receipt-only result. `McpClient` tops a channel up this way when its deposit does not cover the call, and `McpClient::management` returns the transport for closing. Before, an MCP session whose deposit ran out failed with `session cumulative amount exceeds channel deposit`.

`ToolCaller::receipt_from_output` and `mcp::extract_receipt` read a result's receipt. `McpClient` passes the receipt of each paid call to the provider, and `McpPayment::record_receipt` does so for SDK adapters that run their own retry.
