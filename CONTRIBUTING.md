# Contributing

Thanks for looking. Issues and pull requests are welcome. For anything that
could let a call through that should have been refused, please follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Before you open a pull request

- `gofmt -l .` prints nothing, and `go vet ./...` passes.
- `go test ./...` passes, including the end-to-end tests in
  `testing/mcpgate` (they need Docker or local Archytan Lite binaries; the
  README says how).
- A change to what gets authorized, forwarded or refused comes with a test
  that fails without it. Test the refusal, not only the call that goes
  through: most of what matters here is what the MCP gate stops.

## The one rule

The MCP gate decides on one reading of a message, and a host or tool server
may parse the same bytes another way. So a message that can be read two
ways is refused, never normalized into one of its readings. Changes that
make the gate more lenient about ambiguous input won't be accepted; changes
that find more of it are very welcome.

## Sign your commits

Every commit needs a `Signed-off-by` line, which says you wrote it or have
the right to submit it under the project's license, as the
[Developer Certificate of Origin](https://developercertificate.org/)
describes. `git commit -s` adds it.

Contributions are licensed under the Apache License 2.0, the same as the
rest of the repository.
