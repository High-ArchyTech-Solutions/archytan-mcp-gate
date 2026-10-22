// PreToolUse hook for a locked Claude Code workspace. Only the tools named on
// its command line, and the few below that can't reach the machine, may run.
// Every other call is refused, including tools a host such as Claude Desktop
// adds to a session that a settings deny rule can't remove. Any error here
// fails the hook, and the workspace's settings set onFailure "block", so a
// broken hook refuses the call instead of letting it through.
//
//   node gate-only.js <tool or mcp__<server>__ prefix> [...]
//
// An argument ending in "__" allows every tool of that MCP server, such as
// mcp__Archytan_Lite_MCP_gate__; any other argument allows that one tool.
"use strict";

const ALWAYS = new Set(["ToolSearch", "EnterPlanMode", "ExitPlanMode"]);
const ALWAYS_PREFIXES = ["mcp__ccd_turn__"]; // Claude Desktop's plan and next-step boxes

const names = new Set(ALWAYS);
const prefixes = [...ALWAYS_PREFIXES];
const args = process.argv.slice(2);
if (args.length === 0) {
  throw new Error("gate-only.js: name at least one tool or mcp__<server>__ prefix to allow");
}
for (const arg of args) {
  if (arg.endsWith("__")) {
    // A whole server, never a wider pattern: "mcp__" alone would allow every MCP tool.
    if (!/^mcp__[A-Za-z0-9-][A-Za-z0-9_-]*__$/.test(arg)) {
      throw new Error("gate-only.js: not a server prefix: " + JSON.stringify(arg));
    }
    prefixes.push(arg);
  } else {
    if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(arg)) {
      throw new Error("gate-only.js: not a tool name: " + JSON.stringify(arg));
    }
    names.add(arg);
  }
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  const name = JSON.parse(input).tool_name;
  if (typeof name !== "string" || name === "") {
    throw new Error("gate-only.js: hook input has no tool_name");
  }
  if (names.has(name) || prefixes.some((p) => name.startsWith(p))) {
    return; // allowed: no output, so the call goes on to the usual permission checks
  }
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason:
          name +
          " is turned off in this locked workspace. The MCP gate's tools are the only way to what it protects.",
      },
    }),
  );
});
