# Locked workspace for Claude Code and Claude Desktop

The MCP gate decides every tool call that goes through it. It can't decide
a call that goes around it, and Claude Code gives Claude plenty of ways
around: its own Read, Write and Edit tools, a shell, and in Claude Desktop
a terminal, a browser, screen control and tools that start other sessions.
In our first Claude Desktop test, Claude wrote a file the gate's policy
refuses by using its own Write tool, and the gate never saw it.

This kit makes a workspace folder where that can't happen. Sessions started
in it can reach the paths you protect only through the MCP gate's tools.

## Make one

You need Node.js 18 or later, and Claude Code 2.1.295 or later (Claude
Desktop ships its own; 2.1.304 and 2.1.308 are tested). Set up the MCP gate
in the host first: the [MCP bundle](../README.md#install) in Claude
Desktop, or an `mcpServers` entry for Claude Code.

```sh
node locked-workspace/new-workspace.mjs \
  --workspace ~/agent-workspace \
  --protect ~/agent-files \
  --protect ~/archytan/agent.token
```

- `--protect` takes each folder or file the agent must reach only through
  the gate: the tool server's folder, the agent's token, the gate
  service's files. Name as many as you like.
- `--server` is the MCP gate's server name as the host shows it. The
  default, `Archytan Lite MCP gate`, is the name the MCP bundle installs
  under in Claude Desktop. For a Claude Code entry named `archytan-files`,
  pass `--server archytan-files`.
- `--allow` adds a tool the agent may still use, such as `WebSearch`. It
  refuses any tool that can touch the machine.

It writes `.claude/settings.json`, `.claude/hooks/gate-only.js` and a
`CLAUDE.md` into the workspace, and won't overwrite any of them. The
workspace and the protected paths have to be kept apart: neither may be
inside the other.

## Use it

Start the session **on your own machine, in the workspace**:

- **Claude Desktop:** the Code tab. In the row under the prompt box, set
  the environment to **Local** and the project folder to the workspace.
- **Claude Code:** run `claude` in the workspace.

A cloud session doesn't run Claude Code on your machine, so none of this
applies to it. Claude Desktop shows a cloud task's folder request as
"Because this task runs in the cloud, files Claude uses leave your
device". Never give a cloud session access to a protected path: it could
read and change it directly.

## How it works

Two layers, both enforced by Claude Code, not by asking the model:

1. **Deny rules.** They remove Claude's shell, file-writing, search,
   subagent and messaging tools from the session entirely. `Read` stays
   available for the workspace itself, since denying it outright also
   stops `CLAUDE.md` from loading, and gets a deny rule for each
   protected path.
2. **A PreToolUse hook that allows only what it names.** Before every
   tool call, `gate-only.js` lets through the MCP gate's tools, tool
   search, plan mode and Claude Desktop's plan and next-step boxes, and
   refuses everything else. That covers the tools Claude Desktop adds to
   a session, which its deny rules don't remove, and any tool a future
   version adds. If the hook fails to run, times out or gets input it
   can't read, `onFailure: "block"` refuses the call.

Inside the workspace, a refused call comes back to Claude as an error that
names the tool:

```text
PreToolUse:mcp__terminal__run_in_terminal hook error: mcp__terminal__run_in_terminal
is turned off in this locked workspace. The MCP gate's tools are the only way
to what it protects.
```

## What it doesn't cover

- Sessions started anywhere else, and cloud sessions (see above).
- Anything you run yourself, and other programs on the machine. It limits
  the agent's session, not the computer.
- On native Windows, Claude Code has no OS-level sandbox, so these limits
  are enforced by Claude Code. On macOS, Linux and WSL2, Claude Code's
  [sandbox](https://code.claude.com/docs/en/sandboxing) can add OS-level
  limits on top.
- What the gate itself allows. The policy decides which actions the agent
  may take, and the tool server's configuration sets its reach.

## How it was tested

On Windows 11 with Claude Desktop 3.1623.1:

- A real Claude Desktop session (Code tab, Local, Claude Code 2.1.308) in
  a workspace with these rules and this hook, written by hand just before
  the script existed: the gate allowed a list and a read and refused a
  write, and Claude Desktop's own terminal tool was refused by the hook
  before anything ran.
- Claude Desktop's Claude Code 2.1.308, headless in `bypassPermissions`
  mode, in a workspace this script made: the gate's tools went through to
  Archytan Lite (allow, allow, refuse); the shell, Write and Edit weren't
  there; a second MCP server, web search and Read were refused by the
  hook; and a Read through the 8.3 short form of a protected path, which
  the path rule didn't match, was refused by the hook.
- The same with 2.1.304 and the hand-written workspace, plus a copy whose
  hook script was missing: every call was refused.

`node --test locked-workspace/test/kit.test.mjs` runs the kit's own tests,
in CI on Linux, Windows and macOS. They check the hook's decision for
allowed tools, refused tools, lookalike names and unreadable input, and
the workspace the script writes, including what it refuses to write.
macOS and Linux haven't been tried with a live host yet.
