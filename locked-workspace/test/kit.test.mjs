// Tests for the locked-workspace kit: the hook's decision for every kind of
// tool name and input, and the workspace new-workspace.mjs writes.
//
//   node --test locked-workspace/test/kit.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { rulePath, toolPrefix } from "../new-workspace.mjs";

const KIT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const HOOK = path.join(KIT, "gate-only.js");
const NEW = path.join(KIT, "new-workspace.mjs");
const GATE = "mcp__Archytan_Lite_MCP_gate__";

// What Claude Code takes from a hook: a failure (any exit but 0 or 2, which
// onFailure "block" turns into a refusal), no output (the call goes on), or
// a JSON decision.
function decide(command, args, input) {
  const r = spawnSync(command, args, { input, encoding: "utf8" });
  if (r.status !== 0) return "failed";
  if (r.stdout === "") return "allow";
  const out = JSON.parse(r.stdout).hookSpecificOutput;
  assert.equal(out.hookEventName, "PreToolUse");
  return out.permissionDecision;
}
const hook = (args, toolName) => decide(process.execPath, [HOOK, ...args], JSON.stringify({ tool_name: toolName, tool_input: {} }));

test("the gate's tools and the always-allowed ones run", () => {
  for (const t of [GATE + "list_directory", GATE + "write_file", "ToolSearch", "EnterPlanMode", "ExitPlanMode", "mcp__ccd_turn__wrap_up"]) {
    assert.equal(hook([GATE], t), "allow", t);
  }
});

test("a tool named on the command line runs, and only that one", () => {
  assert.equal(hook([GATE, "WebSearch"], "WebSearch"), "allow");
  assert.equal(hook([GATE, "WebSearch"], "WebFetch"), "deny");
  assert.equal(hook([GATE], "WebSearch"), "deny");
});

test("everything else is refused, with the tool's name in the reason", () => {
  for (const t of [
    "PowerShell", "Bash", "Read", "Write", "Edit", "Monitor", "Agent", "Artifact",
    "mcp__terminal__run_in_terminal", "mcp__scheduled-tasks__create_scheduled_task",
    "mcp__ccd_session__start_session", "mcp__computer-use__screenshot", "mcp__other-files__write_file",
    "FetchInboxMessage",
  ]) {
    const r = spawnSync(process.execPath, [HOOK, GATE], { input: JSON.stringify({ tool_name: t }), encoding: "utf8" });
    assert.equal(r.status, 0, t);
    const out = JSON.parse(r.stdout).hookSpecificOutput;
    assert.equal(out.permissionDecision, "deny", t);
    assert.ok(out.permissionDecisionReason.startsWith(t + " is turned off"), t);
  }
});

test("names that only look like an allowed one are refused", () => {
  for (const t of [
    "mcp__Archytan_Lite_MCP_gatex__write_file", "mcp__archytan_lite_mcp_gate__write_file",
    "xmcp__Archytan_Lite_MCP_gate__write_file", "mcp__evil__mcp__Archytan_Lite_MCP_gate__write_file",
    "mcp__Archytan_Lite_MCP_gate", "ToolSearchX", "toolsearch", "mcp__ccd_turnx__wrap_up", " ToolSearch",
  ]) {
    assert.equal(hook([GATE], t), "deny", t);
  }
});

test("input it can't read fails the hook, so the call is blocked", () => {
  for (const input of ["", "not json", "null", "[]", "{}", '{"tool_name":""}', '{"tool_name":7}', '{"tool_name":["ToolSearch"]}']) {
    assert.equal(decide(process.execPath, [HOOK, GATE], input), "failed", input);
  }
});

test("a command line that allows too much, or nothing, fails the hook", () => {
  for (const args of [[], ["mcp__"], ["mcp____"], ["mcp___x__"], ["*"], ["mcp__*__"], ["mcp__a b__"], ["Bash Write"], [""], [GATE, "Read(**)"]]) {
    assert.equal(decide(process.execPath, [HOOK, ...args], JSON.stringify({ tool_name: "ToolSearch" })), "failed", JSON.stringify(args));
  }
});

test("rule paths and tool prefixes", () => {
  assert.equal(rulePath("C:\\Users\\High ArchyTech.a\\Desktop\\files", "win32"), "//c/Users/High ArchyTech.a/Desktop/files");
  assert.equal(rulePath("D:\\x [1]\\", "win32"), "//d/x \\[1\\]");
  assert.equal(rulePath("/home/a b/x[1]*?", "linux"), "//home/a b/x\\[1\\]\\*\\?");
  assert.throws(() => rulePath("\\\\server\\share\\x", "win32"));
  assert.equal(toolPrefix("Archytan Lite MCP gate"), GATE);
  assert.equal(toolPrefix("archytan-files"), "mcp__archytan-files__");
  assert.equal(toolPrefix("my.server"), "mcp__my_server__");
});

function fixture() {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "locked-ws-")));
  const files = path.join(root, "demo files [1]");
  fs.mkdirSync(files);
  fs.writeFileSync(path.join(files, "welcome.txt"), "hello\n");
  const token = path.join(root, "agent.token");
  fs.writeFileSync(token, "not a real token\n");
  return { root, files, token, ws: path.join(root, "workspace") };
}
const make = (...args) => spawnSync(process.execPath, [NEW, ...args], { encoding: "utf8" });

test("new-workspace writes a workspace whose hook lets only the gate through", () => {
  const f = fixture();
  const r = make("--workspace", f.ws, "--protect", f.files, "--protect", f.token);
  assert.equal(r.status, 0, r.stderr);

  const settings = JSON.parse(fs.readFileSync(path.join(f.ws, ".claude", "settings.json"), "utf8"));
  const deny = settings.permissions.deny;
  for (const t of ["Bash", "PowerShell", "Monitor", "Edit", "Write", "NotebookEdit", "Glob", "Grep", "Agent", "Artifact", "SendMessage", "mcp__terminal"]) {
    assert.ok(deny.includes(t), t);
  }
  assert.ok(!deny.includes("Read"), "a bare Read deny would stop CLAUDE.md from loading");
  const reads = deny.filter((d) => d.startsWith("Read("));
  assert.equal(reads.length, 2);
  assert.ok(reads[0].startsWith("Read(//") && reads[0].endsWith("\\[1\\]/**)"), reads[0]);
  assert.ok(reads[1].startsWith("Read(//") && reads[1].endsWith("/agent.token)"), reads[1]);
  if (process.platform === "win32") {
    for (const rule of reads) assert.match(rule, /^Read\(\/\/[a-z]\/[^\\]*(\\[[\]][^\\]*)*\)$/);
  }

  assert.equal(settings.hooks.PreToolUse.length, 1);
  const entry = settings.hooks.PreToolUse[0];
  assert.equal(entry.matcher, "*");
  assert.equal(entry.hooks.length, 1);
  const h = entry.hooks[0];
  assert.equal(h.type, "command");
  assert.equal(h.onFailure, "block");
  assert.equal(h.command, process.execPath);
  assert.ok(h.timeout > 0);
  assert.deepEqual(h.args.slice(1), [GATE]);
  assert.equal(h.args[0], path.join(f.ws, ".claude", "hooks", "gate-only.js"));
  assert.deepEqual(fs.readFileSync(h.args[0]), fs.readFileSync(HOOK));

  // The hook as the settings run it.
  const run = (name) => decide(h.command, h.args, JSON.stringify({ tool_name: name }));
  assert.equal(run(GATE + "read_text_file"), "allow");
  assert.equal(run("PowerShell"), "deny");
  assert.equal(run("mcp__terminal__run_in_terminal"), "deny");

  const md = fs.readFileSync(path.join(f.ws, "CLAUDE.md"), "utf8");
  assert.ok(md.includes(f.files) && md.includes(f.token) && md.includes("Archytan Lite MCP gate"));
});

test("new-workspace never overwrites a workspace", () => {
  const f = fixture();
  assert.equal(make("--workspace", f.ws, "--protect", f.files).status, 0);
  const settingsPath = path.join(f.ws, ".claude", "settings.json");
  const before = fs.readFileSync(settingsPath, "utf8");
  const again = make("--workspace", f.ws, "--protect", f.token, "--allow", "WebSearch");
  assert.equal(again.status, 2);
  assert.match(again.stderr, /already exists/);
  assert.equal(fs.readFileSync(settingsPath, "utf8"), before);

  const mdOnly = path.join(f.root, "has-claude-md");
  fs.mkdirSync(mdOnly);
  fs.writeFileSync(path.join(mdOnly, "CLAUDE.md"), "mine\n");
  assert.equal(make("--workspace", mdOnly, "--protect", f.files).status, 2);
  assert.equal(fs.readFileSync(path.join(mdOnly, "CLAUDE.md"), "utf8"), "mine\n");
  assert.ok(!fs.existsSync(path.join(mdOnly, ".claude", "settings.json")));
});

test("new-workspace refuses what would weaken the lock", () => {
  const f = fixture();
  const cases = [
    ["workspace inside a protected folder", ["--workspace", path.join(f.files, "ws"), "--protect", f.files]],
    ["protected folder inside the workspace", ["--workspace", f.root, "--protect", f.files]],
    ["no protected path", ["--workspace", f.ws]],
    ["a protected path that doesn't exist", ["--workspace", f.ws, "--protect", path.join(f.root, "nope")]],
    ["a server the workspace turns off", ["--workspace", f.ws, "--protect", f.files, "--server", "terminal"]],
    ["a server with no usable name", ["--workspace", f.ws, "--protect", f.files, "--server", "."]],
    ["allowing the shell", ["--workspace", f.ws, "--protect", f.files, "--allow", "Bash"]],
    ["allowing Read", ["--workspace", f.ws, "--protect", f.files, "--allow", "Read"]],
    ["allowing every MCP tool", ["--workspace", f.ws, "--protect", f.files, "--allow", "mcp__"]],
    ["allowing Claude Desktop's terminal", ["--workspace", f.ws, "--protect", f.files, "--allow", "mcp__terminal__"]],
    ["allowing one of its terminal tools", ["--workspace", f.ws, "--protect", f.files, "--allow", "mcp__terminal__run_in_terminal"]],
    ["an unknown option", ["--workspace", f.ws, "--protect", f.files, "--force"]],
  ];
  for (const [what, args] of cases) {
    const r = make(...args);
    assert.equal(r.status, 2, what + ": " + r.stdout + r.stderr);
  }
  assert.ok(!fs.existsSync(path.join(f.ws, ".claude", "settings.json")));
  assert.ok(!fs.existsSync(path.join(f.root, ".claude")));
});

test("new-workspace protects the real folder behind a link", () => {
  const f = fixture();
  const link = path.join(f.root, "shortcut");
  fs.symlinkSync(f.files, link, process.platform === "win32" ? "junction" : "dir");
  assert.equal(make("--workspace", f.ws, "--protect", link).status, 0);
  const deny = JSON.parse(fs.readFileSync(path.join(f.ws, ".claude", "settings.json"), "utf8")).permissions.deny;
  const rule = deny.find((d) => d.startsWith("Read("));
  assert.ok(rule.endsWith("/demo files \\[1\\]/**)") && !rule.includes("shortcut"), rule);
  assert.ok(fs.readFileSync(path.join(f.ws, "CLAUDE.md"), "utf8").includes("- " + f.files + "\n"));
});

test("new-workspace takes another server name, extra tools and a path with ..", () => {
  const f = fixture();
  const roundabout = path.join(f.files, "..", path.basename(f.files));
  const r = make("--workspace", f.ws, "--protect", roundabout, "--server", "archytan-files", "--allow", "WebSearch");
  assert.equal(r.status, 0, r.stderr);
  const h = JSON.parse(fs.readFileSync(path.join(f.ws, ".claude", "settings.json"), "utf8")).hooks.PreToolUse[0].hooks[0];
  assert.deepEqual(h.args.slice(1), ["mcp__archytan-files__", "WebSearch"]);
  assert.equal(decide(h.command, h.args, JSON.stringify({ tool_name: "mcp__archytan-files__read_text_file" })), "allow");
  assert.equal(decide(h.command, h.args, JSON.stringify({ tool_name: GATE + "read_text_file" })), "deny");
  assert.ok(fs.readFileSync(path.join(f.ws, "CLAUDE.md"), "utf8").includes("- " + f.files + "\n"));
});
