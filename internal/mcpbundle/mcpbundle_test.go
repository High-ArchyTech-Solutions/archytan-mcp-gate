// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpbundle

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// fakeRelease writes stand-in binaries and returns the dist directory.
func fakeRelease(t *testing.T) string {
	t.Helper()
	dist := t.TempDir()
	for _, name := range Binaries {
		if err := os.WriteFile(filepath.Join(dist, name), []byte("binary "+name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dist
}

func build(t *testing.T, dist string) []byte {
	t.Helper()
	version, err := ManifestVersion()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Build(&buf, version, dist, filepath.Join("..", "..")); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestBuild_IsReproducible(t *testing.T) {
	dist := fakeRelease(t)
	a, b := build(t, dist), build(t, dist)
	if !bytes.Equal(a, b) {
		t.Fatal("two builds from the same inputs differ")
	}
}

func TestBuild_Contents(t *testing.T) {
	raw := build(t, fakeRelease(t))
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		wantMode := os.FileMode(0o644)
		if strings.HasPrefix(f.Name, "server/") {
			wantMode = 0o755
		}
		if f.Mode() != wantMode {
			t.Errorf("%s has mode %v, want %v", f.Name, f.Mode(), wantMode)
		}
		if f.Method != zip.Store {
			t.Errorf("%s is compressed (method %d)", f.Name, f.Method)
		}
		if f.Flags&0x8 != 0 {
			t.Errorf("%s has a data descriptor, so its local header has no sizes", f.Name)
		}
		if got := f.Modified.UTC().Format("2006-01-02 15:04:05"); got != "1980-01-01 00:00:00" {
			t.Errorf("%s is dated %s", f.Name, got)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		if f.Name == "manifest.json" && !bytes.Equal(data, Manifest) {
			t.Error("the bundled manifest isn't the embedded one")
		}
	}
	want := []string{"LICENSE", "NOTICE", "manifest.json"}
	for _, b := range Binaries {
		want = append(want, "server/"+b)
	}
	want = append(want, "server/launch.sh")
	sort.Strings(want)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("entries %v, want %v in that order", names, want)
	}
}

func TestBuild_RefusesAnotherVersion(t *testing.T) {
	err := Build(io.Discard, "0.0.1", fakeRelease(t), filepath.Join("..", ".."))
	if err == nil || !strings.Contains(err.Error(), "manifest.json declares version") {
		t.Fatalf("want a refusal naming the manifest's version, got %v", err)
	}
}

func TestBuild_RefusesAMissingBinary(t *testing.T) {
	dist := fakeRelease(t)
	if err := os.Remove(filepath.Join(dist, "archytan-mcp-gate-linux-arm64")); err != nil {
		t.Fatal(err)
	}
	version, _ := ManifestVersion()
	if err := Build(io.Discard, version, dist, filepath.Join("..", "..")); err == nil {
		t.Fatal("built a bundle without the linux-arm64 binary")
	}
}

type manifest struct {
	ManifestVersion string `json:"manifest_version"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Server          struct {
		Type       string `json:"type"`
		EntryPoint string `json:"entry_point"`
		MCPConfig  struct {
			Command   string            `json:"command"`
			Args      []string          `json:"args"`
			Env       map[string]string `json:"env"`
			Overrides map[string]struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"platform_overrides"`
		} `json:"mcp_config"`
	} `json:"server"`
	UserConfig map[string]struct {
		Type     string `json:"type"`
		Required bool   `json:"required"`
	} `json:"user_config"`
}

// The manifest has to start the gate the way the gate expects: the config
// file as --config and the three settings in its environment, each one
// something the host asks the user for.
func TestManifest_StartsTheGate(t *testing.T) {
	var m manifest
	var loose map[string]any
	if err := json.Unmarshal(Manifest, &loose); err != nil {
		t.Fatalf("manifest.json isn't JSON: %v", err)
	}
	if err := json.Unmarshal(Manifest, &m); err != nil {
		t.Fatal(err)
	}
	if m.ManifestVersion != "0.3" || m.Name != "archytan-mcp-gate" || m.Server.Type != "binary" {
		t.Fatalf("manifest header %q %q %q", m.ManifestVersion, m.Name, m.Server.Type)
	}
	if m.Server.EntryPoint != "server/launch.sh" {
		t.Fatalf("entry_point %q", m.Server.EntryPoint)
	}
	mc := m.Server.MCPConfig
	if mc.Command != "/bin/sh" || strings.Join(mc.Args, " ") != "${__dirname}/server/launch.sh --config ${user_config.config_path}" {
		t.Fatalf("unix command %q %q", mc.Command, mc.Args)
	}
	win, ok := mc.Overrides["win32"]
	if !ok || win.Command != "${__dirname}/server/archytan-mcp-gate-windows-amd64" || strings.Join(win.Args, " ") != "--config ${user_config.config_path}" {
		t.Fatalf("windows command %+v", win)
	}
	if len(mc.Overrides) != 1 {
		t.Fatalf("unexpected platform overrides %v", mc.Overrides)
	}
	wantEnv := map[string]string{
		"ARCHYTAN_MCP_GATE_URL":               "${user_config.gate_url}",
		"ARCHYTAN_MCP_GATE_CALLER_TOKEN_PATH": "${user_config.caller_token_path}",
		"ARCHYTAN_MCP_GATE_PUBLIC_KEY_HEX":    "${user_config.public_key_hex}",
	}
	if len(mc.Env) != len(wantEnv) {
		t.Fatalf("env %v", mc.Env)
	}
	for k, v := range wantEnv {
		if mc.Env[k] != v {
			t.Fatalf("env %s = %q, want %q", k, mc.Env[k], v)
		}
	}
	// Every ${user_config.X} the command uses is asked for and required,
	// and nothing is asked for that the command doesn't use.
	used := map[string]bool{}
	ref := regexp.MustCompile(`\$\{user_config\.([a-z_]+)\}`)
	for _, s := range append(append(append([]string{}, mc.Args...), win.Args...), mc.Env["ARCHYTAN_MCP_GATE_URL"], mc.Env["ARCHYTAN_MCP_GATE_CALLER_TOKEN_PATH"], mc.Env["ARCHYTAN_MCP_GATE_PUBLIC_KEY_HEX"]) {
		for _, m := range ref.FindAllStringSubmatch(s, -1) {
			used[m[1]] = true
		}
	}
	for key := range used {
		if uc, ok := m.UserConfig[key]; !ok || !uc.Required {
			t.Errorf("the command uses user_config.%s, which isn't a required setting", key)
		}
	}
	for key := range m.UserConfig {
		if !used[key] {
			t.Errorf("user_config.%s is asked for but never used", key)
		}
	}
	for _, key := range []string{"config_path", "caller_token_path"} {
		if m.UserConfig[key].Type != "file" {
			t.Errorf("user_config.%s should be a file picker", key)
		}
	}
}

// server.json is what the MCP Registry lists. It has to name the release
// manifest.json declares and the bundle that release attaches; its hash is
// added by the publish workflow from the signed release, never committed.
func TestServerJSON_MatchesTheManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Name        string `json:"name"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Version     string `json:"version"`
		Packages    []struct {
			RegistryType string  `json:"registryType"`
			Identifier   string  `json:"identifier"`
			FileSha256   *string `json:"fileSha256"`
			Transport    struct {
				Type string `json:"type"`
			} `json:"transport"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	version, _ := ManifestVersion()
	if s.Version != version {
		t.Fatalf("server.json is version %s, manifest.json %s", s.Version, version)
	}
	if s.Name != "io.github.High-ArchyTech-Solutions/archytan-mcp-gate" {
		t.Fatalf("name %q", s.Name)
	}
	if n := len([]rune(s.Description)); n == 0 || n > 100 {
		t.Fatalf("description is %d characters; the registry takes 1 to 100", n)
	}
	if n := len([]rune(s.Title)); n == 0 || n > 100 {
		t.Fatalf("title is %d characters", n)
	}
	if len(s.Packages) != 1 {
		t.Fatalf("want one package, got %d", len(s.Packages))
	}
	p := s.Packages[0]
	wantID := "https://github.com/High-ArchyTech-Solutions/archytan-mcp-gate/releases/download/v" + version + "/" + FileName
	if p.RegistryType != "mcpb" || p.Identifier != wantID {
		t.Fatalf("package %s %s, want mcpb %s", p.RegistryType, p.Identifier, wantID)
	}
	if p.FileSha256 != nil {
		t.Fatal("server.json commits a fileSha256; the publish workflow sets it from the signed release")
	}
	if p.Transport.Type != "stdio" {
		t.Fatalf("transport %q, want stdio", p.Transport.Type)
	}
}

// The launcher runs the build for this machine with the host's arguments
// exactly as given, even when the bundle was unpacked without file modes.
func TestLauncher_RunsTheBuildForThisMachine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the launcher is for macOS and Linux; Windows runs the .exe directly")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("no bundle build for %s", runtime.GOOS)
	}
	dir := filepath.Join(t.TempDir(), "with space", "server")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, "launch.sh")
	if err := os.WriteFile(launcher, Launcher, 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "archytan-mcp-gate-"+runtime.GOOS+"-"+runtime.GOARCH)
	// Mode 0644, as a host that drops modes would leave it.
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nfor a in \"$@\"; do echo \"[$a]\"; done\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/sh", launcher, "--config", "/path/with space/mcp-gate.json", "").CombinedOutput()
	if err != nil {
		t.Fatalf("launcher: %v\n%s", err, out)
	}
	if got, want := string(out), "[--config]\n[/path/with space/mcp-gate.json]\n[]\n"; got != want {
		t.Fatalf("the build got %q, want %q", got, want)
	}

	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command("/bin/sh", launcher).CombinedOutput()
	if err == nil {
		t.Fatalf("launcher succeeded with no build present:\n%s", out)
	}
}
