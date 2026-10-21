// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

// Package mcpbundle builds archytan-mcp-gate.mcpb, the MCP bundle each
// release attaches for hosts that install bundles, and that the MCP
// Registry lists. The bundle holds the gate binaries, a launcher that runs
// the one built for the machine, and manifest.json, which tells the host
// what to ask the user for and how to start the gate.
//
// The bundle is reproducible like the binaries are: entries are stored
// uncompressed, in name order, with one fixed time, fixed modes and their
// sizes in the local headers, so rebuilding it from a release tag gives the
// bytes SHA256SUMS lists.
package mcpbundle

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// FileName is the bundle's name in a release.
const FileName = "archytan-mcp-gate.mcpb"

//go:embed manifest.json
var Manifest []byte

//go:embed launch.sh
var Launcher []byte

// Binaries are the gate builds the bundle carries, named as in a release.
// The launcher picks among the four for macOS and Linux. Windows runs the
// amd64 build, which Windows on Arm runs under emulation, since a bundle
// can choose its command by system but not by CPU.
var Binaries = []string{
	"archytan-mcp-gate-darwin-amd64",
	"archytan-mcp-gate-darwin-arm64",
	"archytan-mcp-gate-linux-amd64",
	"archytan-mcp-gate-linux-arm64",
	"archytan-mcp-gate-windows-amd64.exe",
}

// dosDate1980 is 1980-01-01 in MS-DOS date format, the earliest date a zip
// entry can record; every entry carries it, at time 00:00:00.
const dosDate1980 = 1<<5 | 1

// ManifestVersion returns the version manifest.json declares.
func ManifestVersion() (string, error) {
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(Manifest, &m); err != nil {
		return "", fmt.Errorf("manifest.json: %w", err)
	}
	if m.Version == "" {
		return "", errors.New("manifest.json has no version")
	}
	return m.Version, nil
}

type entry struct {
	name string
	data []byte
	mode fs.FileMode
}

// Build writes the bundle for version to w. dist holds the release
// binaries and root is the repository root, for LICENSE and NOTICE. It
// refuses a version manifest.json doesn't declare, so a release can't ship
// a bundle that names another one.
func Build(w io.Writer, version, dist, root string) error {
	declared, err := ManifestVersion()
	if err != nil {
		return err
	}
	if declared != version {
		return fmt.Errorf("manifest.json declares version %s, but this is %s; update internal/mcpbundle/manifest.json first", declared, version)
	}
	entries := []entry{
		{"manifest.json", Manifest, 0o644},
		{"server/launch.sh", Launcher, 0o755},
	}
	for _, name := range []string{"LICENSE", "NOTICE"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return err
		}
		entries = append(entries, entry{name, data, 0o644})
	}
	for _, name := range Binaries {
		data, err := os.ReadFile(filepath.Join(dist, name))
		if err != nil {
			return err
		}
		entries = append(entries, entry{"server/" + name, data, 0o755})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	zw := zip.NewWriter(w)
	for _, e := range entries {
		h := &zip.FileHeader{
			Name:               e.name,
			Method:             zip.Store,
			ModifiedDate:       dosDate1980,
			CRC32:              crc32.ChecksumIEEE(e.data),
			CompressedSize64:   uint64(len(e.data)),
			UncompressedSize64: uint64(len(e.data)),
		}
		h.SetMode(e.mode)
		// CreateRaw writes the sizes and checksum into the local header,
		// with no data descriptor after the data, so a reader that only
		// streams forward through the archive can read a stored entry too.
		fw, err := zw.CreateRaw(h)
		if err != nil {
			return err
		}
		if _, err := io.Copy(fw, bytes.NewReader(e.data)); err != nil {
			return err
		}
	}
	return zw.Close()
}
