// Copyright 2026 High ArchyTech Solutions
// SPDX-License-Identifier: Apache-2.0

package mcpgate_e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The end-to-end tests need a running Archytan Lite gate service, the
// decision service the MCP gate asks before every tool call. There are two
// ways to get one:
//
//   - ARCHYTAN_LITE_BIN (and ARCHYTAN_LITE_KEYGEN_BIN) name local binaries
//     to run directly;
//   - otherwise Docker runs the published, signed image named by
//     ARCHYTAN_LITE_IMAGE, by default the one pinned below.
//
// With neither available, the tests skip and say why.
//
// 2.7.0 is the first release whose policy can scope a role to named
// resources, which the resource_id_args tests need.
const defaultLiteImage = "ghcr.io/high-archytech-solutions/archytan-lite:2.7.0@sha256:f33cc09b815250e98da52fa65356cee7128652f48b034be5d5436f41a6f4ded4"

// liteService is one running gate service.
type liteService interface {
	// kill stops the service abruptly, the way a crash would.
	kill()
}

type liteBackend struct {
	bin, keygenBin string // local binaries, when set
	image          string // otherwise this image, run with Docker
}

var lite liteBackend

// pickLiteBackend decides once, in TestMain, how the service is run. The
// empty string means it can be; anything else is why it can't.
func pickLiteBackend() string {
	if bin := os.Getenv("ARCHYTAN_LITE_BIN"); bin != "" {
		lite.bin = bin
		lite.keygenBin = os.Getenv("ARCHYTAN_LITE_KEYGEN_BIN")
		if lite.keygenBin == "" {
			return "ARCHYTAN_LITE_BIN is set but ARCHYTAN_LITE_KEYGEN_BIN isn't"
		}
		return ""
	}
	lite.image = os.Getenv("ARCHYTAN_LITE_IMAGE")
	if lite.image == "" {
		lite.image = defaultLiteImage
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		return fmt.Sprintf("no Archytan Lite service: set ARCHYTAN_LITE_BIN, or make Docker available (%v: %s)", err, bytes.TrimSpace(out))
	}
	if out, err := exec.Command("docker", "image", "inspect", lite.image).CombinedOutput(); err != nil {
		if out, err = exec.Command("docker", "pull", "-q", lite.image).CombinedOutput(); err != nil {
			return fmt.Sprintf("could not pull %s: %v: %s", lite.image, err, bytes.TrimSpace(out))
		}
	}
	return ""
}

// dockerUser runs the container as the test's own user on Linux, so it can
// read and write the test's private temp directory. Docker Desktop on
// Windows and macOS maps bind mounts without regard to the uid.
func dockerUser() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	return []string{"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())}
}

var publicKeyHex = regexp.MustCompile(`[0-9a-f]{64}`)

// generateKey writes a new signing key to dir/key.pem with the service's
// own keygen and returns its public key in hex.
func generateKey(t *testing.T, dir string) string {
	t.Helper()
	var cmd *exec.Cmd
	if lite.bin != "" {
		cmd = exec.Command(lite.keygenBin, "-out", filepath.Join(dir, "key.pem"))
	} else {
		args := append([]string{"run", "--rm"}, dockerUser()...)
		args = append(args, "--mount", "type=bind,source="+dir+",target=/cfg",
			"--entrypoint", "keygen", lite.image, "-out", "/cfg/key.pem")
		cmd = exec.Command("docker", args...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	hex := publicKeyHex.Find(out)
	if hex == nil {
		t.Fatalf("keygen printed no public key:\n%s", out)
	}
	return string(hex)
}

// startLite starts the service on addr (host:port) with its files in dir:
// key.pem, callers.json and policy.json, and the database it creates.
func startLite(t *testing.T, dir, addr string) liteService {
	t.Helper()
	env := map[string]string{
		"ARCHYTAN_LITE_CALLERS_PATH":     "callers.json",
		"ARCHYTAN_LITE_DB_PATH":          "archytan.db",
		"ARCHYTAN_LITE_SIGNING_KEY_PATH": "key.pem",
		"ARCHYTAN_LITE_POLICY_PATH":      "policy.json",
	}
	if lite.bin != "" {
		cmd := exec.Command(lite.bin)
		cmd.Env = os.Environ()
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+filepath.Join(dir, v))
		}
		cmd.Env = append(cmd.Env,
			"ARCHYTAN_LITE_INSTANCE_URN=urn:archytan-lite:instance:mcpgate-e2e",
			"ARCHYTAN_LITE_ADDR="+addr,
			"ARCHYTAN_LITE_CAPABILITIES=on")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		p := &localLite{cmd: cmd}
		t.Cleanup(p.kill)
		return p
	}
	_, port, _ := strings.Cut(addr, ":")
	name := fmt.Sprintf("archytan-mcp-gate-e2e-%d-%s", os.Getpid(), port)
	args := append([]string{"run", "-d", "--rm", "--name", name}, dockerUser()...)
	args = append(args, "-p", addr+":8421", "--mount", "type=bind,source="+dir+",target=/cfg")
	for k, v := range env {
		args = append(args, "-e", k+"=/cfg/"+v)
	}
	args = append(args,
		"-e", "ARCHYTAN_LITE_INSTANCE_URN=urn:archytan-lite:instance:mcpgate-e2e",
		"-e", "ARCHYTAN_LITE_ADDR=0.0.0.0:8421",
		"-e", "ARCHYTAN_LITE_CAPABILITIES=on",
		lite.image)
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	c := &containerLite{name: name}
	t.Cleanup(func() {
		if t.Failed() {
			if out, err := exec.Command("docker", "logs", name).CombinedOutput(); err == nil {
				t.Logf("archytan-lite logs:\n%s", out)
			}
		}
		c.kill()
	})
	return c
}

// verifyChain runs the service's own --verify-chain over the database in
// dir, trusting only pubHex, and fails the test unless the chain verifies.
// Stop the service first, so the check reads a database nothing is writing.
func verifyChain(t *testing.T, dir, pubHex string) string {
	t.Helper()
	var cmd *exec.Cmd
	if lite.bin != "" {
		cmd = exec.Command(lite.bin, "--verify-chain")
		cmd.Env = append(os.Environ(),
			"ARCHYTAN_LITE_DB_PATH="+filepath.Join(dir, "archytan.db"),
			"ARCHYTAN_LITE_TRUSTED_PUBLIC_KEYS_HEX="+pubHex)
	} else {
		args := append([]string{"run", "--rm"}, dockerUser()...)
		args = append(args, "--mount", "type=bind,source="+dir+",target=/cfg",
			"-e", "ARCHYTAN_LITE_DB_PATH=/cfg/archytan.db",
			"-e", "ARCHYTAN_LITE_TRUSTED_PUBLIC_KEYS_HEX="+pubHex,
			lite.image, "--verify-chain")
		cmd = exec.Command("docker", args...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the receipt chain did not verify: %v\n%s", err, out)
	}
	return string(out)
}

type localLite struct{ cmd *exec.Cmd }

func (l *localLite) kill() {
	if l.cmd.Process != nil {
		_ = l.cmd.Process.Kill()
		_ = l.cmd.Wait()
	}
}

type containerLite struct{ name string }

func (c *containerLite) kill() {
	_ = exec.Command("docker", "rm", "-f", c.name).Run()
}
