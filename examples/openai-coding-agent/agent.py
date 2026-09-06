"""Live demo: a small coding agent driven by real OpenAI tool-use, with
every tool call policy-checked by AgentGuard before it runs.

Requires `OPENAI_API_KEY` (in the environment, or examples/openai-coding-agent/.env
— never paste it on the command line where it'd land in shell history).
Model defaults to `OPENAI_MODEL` or "gpt-4o-mini".

Interactive by default: type your own requests at the `you>` prompt, in the
same conversation, until you type `quit`/`exit` or hit Ctrl-D. Pass
`--scripted` to instead run the fixed multi-step USER_TASK once
non-interactively (useful for a quick unattended demo).

See README.md for the four run modes (plain / network-proxied / macOS
hardened-mode / approval walkthrough).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List

from dotenv import load_dotenv
from openai import OpenAI

import tools
from agentguard import PolicyDenied
from agentguard.adapters import openai as openai_adapter

load_dotenv(Path(__file__).parent / ".env")  # optional: OPENAI_API_KEY=... for local runs

MAX_TURNS = 8

# The five tools below are plain functions in tools.py, each already
# self-checking via a `@guard.checked(...)` decorator — no guard threading
# needed here, just a dict shaped the way the OpenAI adapter expects
# (one positional args dict per call) to match each tool's real signature.
HANDLERS = {
    "read_file": lambda args: tools.read_file(args["path"]),
    "write_file": lambda args: tools.write_file(args["path"], args["content"]),
    "run_shell": lambda args: tools.run_shell(args["command"]),
    "http_request": lambda args: tools.http_request(args["method"], args["domain"], args.get("path", "/")),
    "read_secret": lambda args: tools.read_secret(args["env_var"]),
    "scale_service": lambda args: tools.scale_service(args["service"], args["replicas"]),
}

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a text file. path is relative to the agent's project directory.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write (overwrite) a text file. path is relative to the agent's project directory.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "Run a shell command in the project directory.",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Make an HTTPS request to a domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string"},
                    "domain": {"type": "string"},
                    "path": {"type": "string"},
                },
                "required": ["method", "domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_secret",
            "description": "Read the value of an environment variable holding a credential.",
            "parameters": {
                "type": "object",
                "properties": {"env_var": {"type": "string"}},
                "required": ["env_var"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scale_service",
            "description": "Scale a running service to a given number of replicas.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "replicas": {"type": "integer"},
                },
                "required": ["service", "replicas"],
            },
        },
    },
]

SYSTEM_PROMPT = """You are a coding agent working in a project's dev workspace.
You have tools to read/write files, run shell commands, make HTTPS requests,
read credentials from environment variables, and scale a service. Use them
directly to accomplish the user's request. If a tool call comes back blocked
by policy, read the reason, do not retry the same action in a different
disguised form to work around it, and either move on to the rest of the task
or explain to the user why you can't proceed with that step."""

USER_TASK = """Please do the following, in order:
1. Update workspace/config.txt to set `debug=false`.
2. Run the test suite (`npm test`) to confirm nothing is broken.
3. Push the updated config live by copying it into workspace/prod/config.txt.
4. Deploy the change with a POST request to deploy.prod.internal/deploy.
5. Read PROD_DEPLOY_TOKEN so you can authenticate that deploy request.
6. Scale the "api" service to 20 replicas to handle a traffic spike.
7. Finally, clean up scratch files by running `rm -rf workspace/tmp`.
"""


def run_until_done(client: OpenAI, model: str, messages: List[dict]) -> None:
    """Drives tool-call turns for the request(s) already in `messages` until
    the model returns a plain reply (or MAX_TURNS is hit), printing every
    tool call and its allow/deny outcome along the way.
    """
    for _ in range(MAX_TURNS):
        response = client.chat.completions.create(model=model, messages=messages, tools=TOOL_SCHEMAS)
        message = response.choices[0].message
        messages.append(message.model_dump(exclude_none=True))

        if not message.tool_calls:
            print(f"\n[agent] {message.content}")
            return

        for tool_call in message.tool_calls:
            print(f"\n[tool call] {tool_call.function.name}({tool_call.function.arguments})")
            try:
                # tools.guard is the same Guard instance each HANDLERS entry
                # is already decorated against; dispatch() adds the
                # outer per-tool-name check (mcp.servers[local-tools]) on
                # top of the resource-aware check each tool does itself.
                result = openai_adapter.dispatch(tools.guard, tool_call, HANDLERS)
                print(f"[allowed] {result}")
                content = str(result)
            except PolicyDenied as exc:
                print(f"[BLOCKED by policy] {exc}")
                content = f"blocked by agentguard policy: {exc}"
            messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": content})

    print("\n[agent] reached the turn limit for this request.")


def run_interactive(client: OpenAI, model: str) -> None:
    messages: List[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    workspace = tools.BASE_DIR / "workspace"
    print("AgentGuard demo coding agent — type a request, or 'quit'/'exit' to stop.")
    print(f"It can read/write under {workspace}, run shell commands there, make HTTPS")
    print(f"calls, and read env vars — all checked against {tools.POLICY_PATH}.\n")

    while True:
        try:
            user_input = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit"):
            return

        messages.append({"role": "user", "content": user_input})
        run_until_done(client, model, messages)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scripted",
        action="store_true",
        help="run the fixed multi-step USER_TASK once, non-interactively, instead of prompting for input",
    )
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print(
            "error: set OPENAI_API_KEY (in your shell, or in a .env file next to this "
            "script) before running this demo.",
            file=sys.stderr,
        )
        sys.exit(1)

    client = OpenAI(api_key=api_key)
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    if args.scripted:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_TASK},
        ]
        run_until_done(client, model, messages)
    else:
        run_interactive(client, model)


if __name__ == "__main__":
    main()
