# Example: the MCP proxy, zero code changes

`mcp_server.py` is a plain stdio MCP server (no AgentGuard awareness at all)
exposing three tools: `list_files`, `read_file`, `delete_file`. `client_demo.py`
is a plain MCP client driving it. Point either one at the real server and
they work unmodified.

The only thing that changes to add policy enforcement is the launch command:
instead of spawning `mcp_server.py` directly, `client_demo.py` spawns
`agentctl mcp-proxy --policy policy.yaml --server demo-files -- python3 mcp_server.py`,
which speaks the same MCP protocol on both sides and intercepts every
`tools/call`. `policy.yaml` allows `list_files`/`read_file` and denies
`delete_file` outright — so the delete call comes back as a JSON-RPC error
before it ever reaches the real server process, with no server-side or
client-side code aware that a proxy is involved.

## Run it

```bash
go build -o /tmp/agentctl ../../cli/cmd/agentctl
cd examples/mcp-proxy-demo
python3 client_demo.py /tmp/agentctl
```

Expected output: `list_files` and `read_file` succeed; `delete_file` comes
back as `{"error": {"code": -32000, "message": "blocked by agentguard policy: ..."}}`.

Swap `agentctl mcp-proxy ... -- python3 mcp_server.py` for a real MCP client
config (Claude Desktop, an MCP-compatible agent) and a real reference server
(filesystem, GitHub, etc.) and nothing about this changes — that's the point.
