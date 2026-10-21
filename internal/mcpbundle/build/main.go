// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

// Command build writes archytan-mcp-gate.mcpb from a release's binaries:
//
//	go run ./internal/mcpbundle/build -version 2.7.0 -dist dist
//
// The release workflow runs it after building the binaries, and CI runs it
// to check the bundle builds the same twice.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/high-archytech-solutions/archytan-mcp-gate/v2/internal/mcpbundle"
)

func main() {
	version := flag.String("version", "", "the release version, without the v (required)")
	dist := flag.String("dist", "dist", "directory holding the release binaries")
	out := flag.String("out", "", "where to write the bundle (default: <dist>/"+mcpbundle.FileName+")")
	flag.Parse()
	if *version == "" {
		fmt.Fprintln(os.Stderr, "build: -version is required")
		os.Exit(2)
	}
	if *out == "" {
		*out = filepath.Join(*dist, mcpbundle.FileName)
	}
	var buf bytes.Buffer
	if err := mcpbundle.Build(&buf, *version, *dist, "."); err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes)\n", *out, buf.Len())
}
