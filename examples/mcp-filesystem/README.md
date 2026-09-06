# Example: policy-checking an MCP server with zero code changes

The strongest demo in the whole project: point an MCP client at the proxy
instead of the real server, and nothing else changes.

Given an MCP client config that currently launches a server directly:

```json
{
  "mcpServers": {
    "payments": {
      "command": "npx",
      "args": ["-y", "@some-org/payments-mcp-server"]
    }
  }
}
```

Change only the `command`/`args` to launch it through the proxy instead:

```json
{
  "mcpServers": {
    "payments": {
      "command": "agentctl",
      "args": [
        "mcp-proxy",
        "--policy", "/absolute/path/to/policy.yaml",
        "--server", "payments-mcp",
        "--",
        "npx", "-y", "@some-org/payments-mcp-server"
      ]
    }
  }
}
```

`--server` must match the server name used under `mcp.servers[].name` in
your policy (see `../../policy-spec/examples/payments-mcp.yaml`). Every
`tools/call` the client makes now goes through policy first: allowed calls
reach the real server unchanged, denied calls get a JSON-RPC error back
without the real server ever seeing them, and calls marked
`require_approval: true` prompt on the terminal `agentctl mcp-proxy` is
running in.
