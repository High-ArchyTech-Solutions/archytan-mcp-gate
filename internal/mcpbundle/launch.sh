#!/bin/sh
# Copyright 2026 High ArchyTech Solutions
# SPDX-License-Identifier: Apache-2.0
#
# Runs the archytan-mcp-gate build for this machine with the arguments the
# MCP host passed. The bundle carries one build per system and CPU, and a
# bundle's manifest can choose its command by system but not by CPU.
dir=$(cd "$(dirname "$0")" && pwd) || exit 1
case $(uname -s) in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) echo "archytan-mcp-gate: this bundle has no build for $(uname -s)" >&2; exit 1 ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) echo "archytan-mcp-gate: this bundle has no build for $(uname -m)" >&2; exit 1 ;;
esac
bin="$dir/archytan-mcp-gate-$os-$arch"
# A host may unpack the bundle without keeping file modes.
[ -x "$bin" ] || chmod +x "$bin" || exit 1
exec "$bin" "$@"
