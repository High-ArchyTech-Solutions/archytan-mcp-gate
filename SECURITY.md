# Security

## Reporting a vulnerability

Please report security problems in the MCP gate privately, not in a public
issue:

- use **Report a vulnerability** on this repository's
  [Security tab](https://github.com/High-ArchyTech-Solutions/archytan-mcp-gate/security), or
- email contact@high-archy.tech.

Include the version you ran, the host and tool server, what you sent, what
happened and what you expected. Leave out real tokens and signing keys.

We'll acknowledge your report, keep you informed while we investigate, and
credit you in the advisory if you'd like to be named. Problems in the
Archytan Lite gate service itself go to
[archytan-lite-community](https://github.com/High-ArchyTech-Solutions/archytan-lite-community/security).

One class of report is especially welcome: a message that the MCP gate and
a host or tool server read differently. The MCP gate holds to one rule
here. A message has to have exactly one reading before anything about it is
authorized, so anything that can be read two ways is refused rather than
normalized. If you find a way past that, we want to know.

## Supported versions

| Version | Security fixes |
|---|---|
| 2.6.x | Yes |
| 2.5.x | Yes, for those who can't take 2.6's protocol changes yet |
| Earlier | No: upgrade |

## Advisories

| Advisory | Severity | Affected | Fixed |
|---|---|---|---|
| [GHSA-9ff5-c4g4-rx92](https://github.com/High-ArchyTech-Solutions/archytan-lite-community/security/advisories/GHSA-9ff5-c4g4-rx92): the MCP gate could read a crafted message differently from the server behind it | High | 2.2.0 to 2.5.0 | 2.5.1, 2.6.0 |

Advisories from before this repository existed are published on
archytan-lite-community, where those releases shipped.
