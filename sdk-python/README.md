# agentguard (Python SDK)

Thin client for the AgentGuard daemon: wrap an agent's tools so every call is
policy-checked before it runs. All decision logic lives in the Go daemon —
this SDK only translates a tool call into a request over the daemon's Unix
socket and enforces the response. See `../policy-spec/schema.yaml` for the
policy DSL and `../CHANGELOG.md` for why the SDK is designed this way.

## Quickstart

```python
from agentguard import Guard

guard = Guard(policy="policy.yaml")  # starts the daemon if one isn't already running
tools = guard.wrap_tools([github_search_tool, file_write_tool, shell_tool])
agent = create_react_agent(llm, tools)  # rest of your agent code is unchanged
```

Or for a manual dispatch loop (raw OpenAI/Anthropic tool calling):

```python
result = guard.check_and_execute(tool_name, tool_args, execute_fn=my_dispatch_fn)
```

## Development

```bash
pip install -e ".[dev]"
pytest
```
