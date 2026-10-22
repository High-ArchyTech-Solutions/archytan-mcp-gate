// Makes a locked Claude Code workspace: a folder where Claude Code, and
// Claude Desktop's Code tab with the Local environment, can reach the paths
// you protect only through the MCP gate. See README.md.
//
//   node new-workspace.mjs --workspace <dir> --protect <path> [--protect <path> ...]
//                          [--server "Archytan Lite MCP gate"] [--allow <tool> ...]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

// Built-in tools that can touch the machine. A bare name removes the tool
// from the session. Read isn't here: denying it outright also stops the
// workspace's CLAUDE.md from loading, so Read gets a rule per protected
// path, and the hook refuses every other Read.
const BUILTIN_DENY = [
  "Bash", "PowerShell", "Monitor", "Edit", "Write", "NotebookEdit", "Glob", "Grep",
  "LSP", "Agent", "EnterWorktree", "SendMessage", "ListAgents", "Artifact",
  "ArtifactComments", "ArtifactData", "DesignSync", "RemoteTrigger",
];
// Claude Desktop's own tool servers. Desktop adds these in a way these rules
// don't remove from the session (2026-10, Desktop 3.1623.1), so the hook is
// what refuses them; the rules stay in case a host honours them.
const HOST_DENY = [
  "mcp__terminal", "mcp__computer-use", "mcp__remote-devices", "mcp__claude-in-chrome",
  "mcp__Claude_Browser", "mcp__scheduled-tasks", "mcp__ccd_session", "mcp__ccd_session_mgmt",
  "mcp__ccd_directory", "mcp__ccd_settings", "mcp__ccd_host", "mcp__ccd_connectors",
];

function fail(message) {
  process.stderr.write("new-workspace: " + message + "\n");
  process.exit(2);
}

// The prefix a host gives a server's tools: characters other than letters,
// digits, "_" and "-" become "_".
export function toolPrefix(server) {
  return "mcp__" + server.replace(/[^A-Za-z0-9_-]/g, "_") + "__";
}

// A permission rule's path: POSIX form, anchored at the filesystem root with
// "//" (C:\Users\a becomes //c/Users/a), gitignore pattern characters escaped.
export function rulePath(absolute, platform = process.platform) {
  let p = absolute;
  if (platform === "win32") {
    const m = /^([A-Za-z]):[\\/](.*)$/.exec(p);
    if (!m) throw new Error("not a drive path: " + p);
    p = "/" + m[1].toLowerCase() + "/" + m[2].replace(/\\/g, "/");
  }
  p = p.replace(/[\\[\]*?]/g, (c) => "\\" + c).replace(/\/+$/, "");
  return "/" + p;
}

function inside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function main() {
  let opts;
  try {
    opts = parseArgs({
      options: {
        workspace: { type: "string" },
        protect: { type: "string", multiple: true },
        server: { type: "string", default: "Archytan Lite MCP gate" },
        allow: { type: "string", multiple: true, default: [] },
      },
      strict: true,
    }).values;
  } catch (err) {
    fail(err.message);
  }
  if (!opts.workspace) fail("--workspace is required");
  if (!opts.protect || opts.protect.length === 0) fail("name at least one --protect path");
  if (opts.server.trim() === "") fail("--server can't be empty");

  const prefix = toolPrefix(opts.server);
  if (!/^mcp__[A-Za-z0-9-][A-Za-z0-9_-]*__$/.test(prefix)) {
    fail("--server " + JSON.stringify(opts.server) + " has to start with a letter, digit or -");
  }
  if (HOST_DENY.some((d) => prefix.startsWith(d + "__"))) {
    fail("--server " + JSON.stringify(opts.server) + " is a name this workspace turns off");
  }
  for (const a of opts.allow) {
    // The hook's own reading: ending in "__" makes it a server prefix.
    const ok = a.endsWith("__") ? /^mcp__[A-Za-z0-9-][A-Za-z0-9_-]*__$/.test(a) : /^[A-Za-z][A-Za-z0-9_-]*$/.test(a);
    if (!ok) fail("--allow takes a tool name or an mcp__<server>__ prefix: " + JSON.stringify(a));
    if (BUILTIN_DENY.includes(a) || a === "Read" || HOST_DENY.some((d) => a.startsWith(d + "__"))) {
      fail("--allow " + a + ": that tool can reach the machine");
    }
  }

  const protectedPaths = opts.protect.map((p) => {
    let real;
    try {
      real = fs.realpathSync.native(path.resolve(p));
    } catch {
      fail("--protect " + p + ": no such file or folder");
    }
    return { real, dir: fs.statSync(real).isDirectory() };
  });

  const workspace = path.resolve(opts.workspace);
  fs.mkdirSync(workspace, { recursive: true });
  const wsReal = fs.realpathSync.native(workspace);
  for (const { real } of protectedPaths) {
    if (inside(wsReal, real) || inside(real, wsReal)) {
      fail("keep the workspace and " + real + " apart: neither may be inside the other");
    }
  }
  const claudeDir = path.join(wsReal, ".claude");
  for (const f of [path.join(claudeDir, "settings.json"), path.join(wsReal, "CLAUDE.md")]) {
    if (fs.existsSync(f)) fail(f + " already exists; this makes a new workspace and won't overwrite it");
  }

  const kitHook = path.join(path.dirname(fileURLToPath(import.meta.url)), "gate-only.js");
  const hook = path.join(claudeDir, "hooks", "gate-only.js");
  fs.mkdirSync(path.dirname(hook), { recursive: true });
  fs.copyFileSync(kitHook, hook);

  const readRules = protectedPaths.map(({ real, dir }) => "Read(" + rulePath(real) + (dir ? "/**" : "") + ")");
  const settings = {
    permissions: { deny: [...BUILTIN_DENY, ...readRules, ...HOST_DENY] },
    hooks: {
      PreToolUse: [
        {
          matcher: "*",
          hooks: [
            {
              type: "command",
              command: process.execPath,
              args: [hook, prefix, ...opts.allow],
              timeout: 15,
              onFailure: "block",
            },
          ],
        },
      ],
    },
  };
  fs.writeFileSync(path.join(claudeDir, "settings.json"), JSON.stringify(settings, null, 2) + "\n");

  const claudeMd = [
    "# Locked workspace",
    "",
    "This workspace is locked so that the only way to reach what it protects is",
    "the MCP gate's tools (the `" + opts.server + "` server). It protects:",
    "",
    ...protectedPaths.map(({ real }) => "- " + real),
    "",
    "The workspace's .claude/settings.json and its hook turn off every other",
    "tool, including the shell and the built-in file tools. When the gate",
    "refuses a call, report the refusal as it came back.",
    "",
  ].join("\n");
  fs.writeFileSync(path.join(wsReal, "CLAUDE.md"), claudeMd);

  process.stdout.write(
    [
      "Locked workspace: " + wsReal,
      "  allows the tools of: " + opts.server + " (" + prefix + "*)" + (opts.allow.length ? ", and " + opts.allow.join(", ") : ""),
      "  protects: " + protectedPaths.map(({ real }) => real).join(", "),
      "",
      "Open it as a local session: in Claude Desktop, the Code tab with the Local",
      "environment and this folder; or run claude in it. A cloud session doesn't",
      "run Claude Code on this machine, so this lock doesn't apply to one: never",
      "give a cloud session access to a protected path.",
      "",
    ].join("\n"),
  );
}

const self = fs.realpathSync.native(fileURLToPath(import.meta.url));
if (process.argv[1] && fs.existsSync(process.argv[1]) && fs.realpathSync.native(process.argv[1]) === self) {
  main();
}
