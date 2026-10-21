# archytan-mcp-gate

`archytan-mcp-gate` sits between an MCP host (Claude Code, Claude Desktop,
an IDE agent, your own agent) and an MCP tool server. Before any tool call
reaches the server, an [Archytan Lite](https://high-archy.tech/lite) gate
service has to authorize it. The MCP gate checks the signed receipt for that
decision and spends a single-use capability, and only then forwards the call.
A call the policy doesn't allow comes back to the agent as a tool error it
can read, and never reaches the server.

This repository is the MCP gate's source, under the Apache License 2.0. The
Archytan Lite gate service it talks to is a separate product, distributed as
a signed container image; its quickstart is in
[archytan-lite-community](https://github.com/High-ArchyTech-Solutions/archytan-lite-community).

## How it works

The host launches the MCP gate in place of the tool server, and the MCP gate
launches the server itself, so it becomes the only path between the agent
and its tools. For every `tools/call` it:

1. asks the Archytan Lite gate service to authorize the action the call maps
   to, on the resource the call names;
2. verifies the receipt the service returns: its fields must hash to the
   signed intent hash, the signature must be the service's key, and the
   receipt must describe exactly this call;
3. redeems the single-use capability that came with the ALLOW;
4. forwards the call to the tool server.

If any step fails, the call is refused and the server never sees it. The
agent never holds anything that could skip these steps: the MCP gate holds
the agent's credential, and the agent only ever speaks MCP.

## Requirements

- An Archytan Lite gate service with capabilities on
  (`ARCHYTAN_LITE_CAPABILITIES=on`). The tests run against version 2.6.0.
- A credential-bound caller for the agent, made with the service's
  `callergen`. The MCP gate never sends a role; the agent's role is whatever
  its credential holds.

## Install

Download the binary for your platform from this repository's
[releases](https://github.com/High-ArchyTech-Solutions/archytan-mcp-gate/releases).
`SHA256SUMS` covers every binary and is signed by the workflow that built
them, with [cosign](https://github.com/sigstore/cosign) keyless signing:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/High-ArchyTech-Solutions/archytan-mcp-gate/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

Or build it yourself with Go:

```sh
go install github.com/high-archytech-solutions/archytan-mcp-gate/v2/cmd/archytan-mcp-gate@latest
```

Each release also attaches `archytan-mcp-gate.mcpb`, an
[MCP bundle](https://github.com/modelcontextprotocol/mcpb) for hosts that
install them, and lists it in the
[MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.High-ArchyTech-Solutions/archytan-mcp-gate`. The host asks for
four things: an `mcp-gate.json` that names the tool server in its
`server` field (see [Configure](#configure)), the gate service's URL, the
agent's token file and the service's public key. The bundle carries the
builds for macOS and Linux on amd64 and arm64, and for Windows on amd64,
which Windows on Arm runs under emulation. `SHA256SUMS` covers it too.
The macOS builds aren't notarized by Apple, so macOS may refuse to run
one that arrived through a browser until you clear its quarantine
(`xattr -d com.apple.quarantine <file>`).

## Configure

Map each tool you want the agent to have to a policy action in
`mcp-gate.json`. `resource_id_arg` names the argument that identifies the
resource the call acts on:

```json
{
  "version": 1,
  "agent_uid": "agent-invoices",
  "tools": {
    "delete_invoice": { "action": "invoice.delete", "resource_type": "invoice", "resource_id_arg": "invoice_id" },
    "read_invoice":   { "action": "invoice.read",   "resource_type": "invoice", "resource_id_arg": "invoice_id" }
  }
}
```

Then point the host at the MCP gate instead of the tool server. The same
`mcpServers` entry works in Claude Desktop's `claude_desktop_config.json`
and a project's `.mcp.json`:

```json
{
  "mcpServers": {
    "invoices": {
      "command": "archytan-mcp-gate",
      "args": ["--config", "/etc/archytan/mcp-gate.json", "--", "node", "/opt/invoice-server/index.js"],
      "env": {
        "ARCHYTAN_MCP_GATE_URL": "https://gate.internal:8421",
        "ARCHYTAN_MCP_GATE_CALLER_TOKEN_PATH": "/etc/archytan/agent-invoices.token",
        "ARCHYTAN_MCP_GATE_PUBLIC_KEY_HEX": "<the gate service's receipt-signing public key>"
      }
    }
  }
}
```

| Variable | Meaning |
|---|---|
| `ARCHYTAN_MCP_GATE_URL` | Base URL of the Archytan Lite gate service. Plain `http` is accepted only to loopback, because every request carries the agent's credential. |
| `ARCHYTAN_MCP_GATE_CALLER_TOKEN_PATH` | File holding the agent's caller token. |
| `ARCHYTAN_MCP_GATE_PUBLIC_KEY_HEX` | The service's Ed25519 receipt-signing public key, in hex. Receipts signed by any other key are refused. |

The tool server can be named in `mcp-gate.json` instead of after `--`,
which suits a host or bundle that only lets you pass a config file:

```json
{
  "version": 1,
  "agent_uid": "agent-invoices",
  "server": { "command": "node", "args": ["/opt/invoice-server/index.js"] },
  "tools": {
    "read_invoice": { "action": "invoice.read", "resource_type": "invoice", "resource_id_arg": "invoice_id" }
  }
}
```

The host's entry is then `"args": ["--config", "/etc/archytan/mcp-gate.json"]`.
The command runs exactly as written and inherits the MCP gate's
environment, the same as after `--`. Name the server in one place: with a
`server` in the config and a command after `--`, the MCP gate refuses to
start rather than pick one.

`mcp-gate.json` is read as strictly as host messages are. An unknown
field, a key that repeats or differs only in case at any depth, and text
that isn't valid UTF-8 or escapes an unpaired surrogate all stop the MCP
gate at startup, so a second `server` can't quietly decide which program
runs.

## What it does on the wire

- **Tools the policy doesn't cover are hidden and refused.** `tools/list`
  shows the agent only mapped tools, and a call to any other name is refused
  without reaching the service or the server. `resources/*`, `prompts/*`,
  `completion/*`, `tasks/*` and unknown methods are refused, and those
  capabilities are removed from what the server advertises.
- **The host can't widen the server's scope.** MCP roots let a host tell a
  server which folders to work in, and servers that honour them (the
  reference filesystem server, for one) swap their configured folders for
  the host's list. Behind the MCP gate, the folders you give the server in
  its command are the ones it keeps: the gate removes roots from what the
  host declares, answers or refuses a server's request for roots, and drops
  roots change notifications.
- **Both protocol generations pass.** The MCP gate relays the `initialize`
  handshake and MCP 2026-07-28: `server/discover`, requests that carry their
  own capabilities, `input_required` round trips for elicitation and
  sampling, and `subscriptions/listen`, narrowed to tool list changes. Each
  round of a call that stops to ask the user something is authorized and
  spent on its own, since each is a call the server may act on.
- **A message that reads two ways is refused.** JSON parsers disagree on an
  object whose keys repeat or differ only in case, and on text that isn't
  valid UTF-8 or escapes an unpaired surrogate. A host message like that is
  refused before anything is authorized or forwarded, so the MCP gate and
  the server always agree on the call that was decided.
- **Refusals read as tool results.** A refused call comes back as a tool
  result with `isError` set and a plain explanation the model can act on.
- **The agent's trace reaches the decision.** A W3C `traceparent` in a tool
  call's `params._meta` is passed to the service, so its log lines and
  version 2 receipt carry the agent's trace id. Trace context never changes
  a decision.
- **Calls run in the order the agent issued them**, while pings,
  notifications and cancellations are never held up behind them.
- **Cancellation is honoured at every step.** Cancelled before the
  capability is redeemed: nothing is spent or executed. Cancelled after
  forwarding: the cancellation is relayed to the server, the only party
  that can still stop it.
- **The tool server doesn't outlive the MCP gate.** When the gate exits it
  closes the server's input, then asks the server to stop, then forces it.
  On Windows the server also runs in a job object, so it's stopped even if
  the gate itself is killed. Elsewhere a killed gate leaves the server to
  exit at the end of its input, as MCP stdio servers do.

## Tested with

| Host or server | Through the MCP gate |
|---|---|
| MCP TypeScript client SDK 2.3.1, `initialize` handshake | Works |
| Same SDK, `auto` negotiation | Works. Reaches a server's MCP 2026-07-28 support, and falls back to `initialize` when the server predates it |
| Same SDK, pinned to 2026-07-28 | Works with a 2026-07-28 server. With an older server it fails at connect, as the SDK intends |
| Same SDK, reusing a cached discovery result | Works, and the host's roots still don't reach the server |
| MCP TypeScript server SDK 2.3.1 (both protocol generations) | Works with every client mode above |
| `@modelcontextprotocol/server-filesystem` 1.0.0 (`initialize` only) | Works, and keeps its configured folder |

## What it doesn't cover

- It protects what the agent reaches through it. Make it the only path:
  list the tool server only through the MCP gate's entry, and give the
  server's own credentials to that entry alone. An agent with a
  general-purpose shell can still start the server by hand.
- The policy decides which actions the agent may take on which resources.
  Within an allowed action, the server's own arguments and configuration set
  its reach.
- It governs tools. Resources, prompts and completions don't pass.

## Security

Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.
Past advisories are listed there, including
[GHSA-9ff5-c4g4-rx92](https://github.com/High-ArchyTech-Solutions/archytan-lite-community/security/advisories/GHSA-9ff5-c4g4-rx92),
fixed in 2.5.1 and 2.6.0.

## Build and test

```sh
go test ./...
```

The tests in `testing/mcpgate` drive the real binary between a scripted
host, a fixture tool server and a real Archytan Lite gate service. By
default they run the published, signed service image with Docker. To use
local binaries instead, set `ARCHYTAN_LITE_BIN` and
`ARCHYTAN_LITE_KEYGEN_BIN`. Without either, they skip and say why; CI sets
`ARCHYTAN_MCP_GATE_E2E_REQUIRED=1` so they can't pass by skipping.

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The
Archytan Lite gate service is licensed separately.
