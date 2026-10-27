# Changelog

Releases up to 2.6.0 were built from Archytan Lite's own repository and
published on
[archytan-lite-community](https://github.com/High-ArchyTech-Solutions/archytan-lite-community/releases).
This repository holds the same code from 2.6.0 on.

## Unreleased

- A tool's resource can be named by several arguments: `resource_id_args`
  joins their values with `/`, for servers such as GitHub's that take
  `owner` and `repo` separately, and `resource_id_path_arg` adds one more,
  joined last, that may span segments, like a branch. With Archytan Lite
  2.7.0's grants, a policy can then scope a role to `acme/web-*`, or to
  `acme/web-*/feature/**` for pushes. A `resource_id_args` value containing
  `/` or `\` is refused, since joined with the others it would name a
  different resource, and a listed argument that's missing is refused
  rather than left out of the id. `resource_id_arg` works as before. An
  MCP gate older than this one refuses a config that uses the new fields.
- The end-to-end tests run against Archytan Lite 2.7.0.
- `locked-workspace/` makes a Claude Code workspace, for Claude Code and
  Claude Desktop's local sessions, where the MCP gate's tools are the only
  way to the paths you protect: deny rules remove Claude's shell and file
  tools, and a PreToolUse hook that fails closed refuses every tool it
  doesn't name, including the ones Claude Desktop adds to a session. No
  change to the MCP gate itself.

## 2.7.0 (2026-10-21)

- Releases attach `archytan-mcp-gate.mcpb`, an MCP bundle for hosts that
  install them, and are listed in the MCP Registry as
  `io.github.High-ArchyTech-Solutions/archytan-mcp-gate`. The bundle is
  covered by the signed `SHA256SUMS` and rebuilds to the same bytes from
  the tag, like the binaries.
- The tool server can be named in `mcp-gate.json`'s `server` (`command`
  and `args`) instead of after `--`, for hosts and bundles that only pass
  a config file. Naming it in both places, or in neither, stops the MCP
  gate at startup.
- `mcp-gate.json` is held to the rule host messages are: an object whose
  keys repeat or differ only in case, at any depth, and text that isn't
  valid UTF-8 or escapes an unpaired surrogate are refused at startup.
  Before, the last of two repeated keys won without a word. A config that
  loaded before and has neither still loads.

## 2.6.3 (2026-10-20)

- Built with Go 1.26.10, which fixes CVE-2026-111943: certificate checks
  refuse chains through eight intermediates from one certificate
  authority. The MCP gate checks the Archytan Lite gate service's
  certificate with Go's verifier, and the agent's credential travels on
  that connection, so a build on an earlier Go could accept a chain
  through them. Nothing else changes.

## 2.6.2 (2026-10-20)

- The MCP gate's source is published here under the Apache License 2.0,
  and releases are built and signed from it. No change in behavior from
  2.6.0.
- The module path is `github.com/high-archytech-solutions/archytan-mcp-gate/v2`,
  as Go requires for version 2 tags, so `go install` can fetch a release.

## 2.6.1 (not released)

- Tagged and built, then withdrawn before release: its module path lacked
  the `/v2` suffix, so Go tools couldn't fetch it by version. The tag stays
  as it was; 2.6.2 is the same code with the corrected path.

## 2.6.0 (2026-10-16)

- Relays MCP 2026-07-28 as well as the `initialize` handshake:
  `server/discover`, requests that carry their own capabilities,
  `input_required` round trips for elicitation and sampling, and
  `subscriptions/listen`, narrowed to tool list changes. The host's roots
  still don't reach the server, and a server that asks for them is refused.
- Refusals of a 2026-07-28 call carry `resultType`, so 2026-07-28 clients
  show the model the reason.
- Carries the fix from 2.5.1.

## 2.5.1 (2026-10-16)

- Security fix for
  [GHSA-9ff5-c4g4-rx92](https://github.com/High-ArchyTech-Solutions/archytan-lite-community/security/advisories/GHSA-9ff5-c4g4-rx92):
  refuses a host message whose keys repeat or differ only in case, or whose
  text isn't valid UTF-8 or escapes an unpaired surrogate, before anything
  is authorized or forwarded.

## 2.5.0 (2026-10-13)

- Passes a W3C `traceparent` from a tool call's `params._meta` to the
  Archytan Lite gate service, so its log lines and version 2 receipts carry
  the agent's trace id.

## 2.3.1 (2026-10-01)

- The host can't widen the tool server's scope through MCP roots: the MCP
  gate removes the host's roots from `initialize`, answers a server's
  `roots/list` itself, and drops roots change notifications.

## 2.3.0 (2026-09-29)

- A refused redemption names the new reason the service can give: the
  action is no longer allowed by the current policy.

## 2.2.0 (2026-09-28)

- First release: every `tools/call` is authorized by the Archytan Lite gate
  service, its receipt verified and its single-use capability redeemed
  before it's forwarded. Signed downloads for macOS, Linux and Windows from
  2.2.1.
