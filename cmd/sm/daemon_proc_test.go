// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

// With $SM_TEST_EXEC=1 the test binary is sm, so the tests can run sm as
// processes.
func TestMain(m *testing.M) {
	if os.Getenv("SM_TEST_EXEC") == "1" {
		os.Exit(run(os.Args, osProc()))
	}
	os.Exit(m.Run())
}

// procConfig is node name of a two-node mesh pa/pb, whose peer is at
// 127.0.0.1:peerPort: no discovery, nothing leaves the host.
func procConfig(name string, i, port, peerPort int, peerPub [32]byte) []byte {
	names := []string{"pa", "pb"}
	b, _ := json.Marshal(map[string]any{
		"name":      name,
		"interface": map[string]any{"addresses": []string{fmt.Sprintf("10.99.0.%d/24", i+1)}, "listen_port": port},
		"peers": []any{map[string]any{
			"name": names[1-i], "public_key": mesh.FormatKey(peerPub),
			"allowed_ips": []string{fmt.Sprintf("10.99.0.%d/32", 2-i)},
			"endpoint":    fmt.Sprintf("127.0.0.1:%d", peerPort),
		}},
		"stun":                     map[string]any{"addresses": []string{"127.0.0.1:9"}},
		"refresh_interval_seconds": 86400,
		"domain":                   "mesh.test",
		"hosts":                    map[string]string{"pa": "10.99.0.1", "pb": "10.99.0.2"},
	})
	return b
}

func fill(b byte) (k [32]byte) {
	for i := range k {
		k[i] = b
	}
	return k
}

// smProc runs the test binary as sm with dir as its runtime directory
// and dir/key as its key.
func smProc(t *testing.T, dir, config string, args ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(exe)
	c.Args = append([]string{"sm", "--config", config}, args...)
	c.Env = append(os.Environ(), "SM_TEST_EXEC=1", "XDG_RUNTIME_DIR="+dir, "STUNMESH_CLI_KEY="+filepath.Join(dir, "key"))
	return c
}

// sm down succeeds with no daemon to stop: no socket, or a stale one.
func TestDownWithoutDaemon(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "pa.json")
	if err := os.WriteFile(config, procConfig("pa", 0, 1, 2, mesh.PublicKey(fill(2))), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := smProc(t, dir, config, "down").CombinedOutput(); err != nil {
		t.Errorf("down without a socket: %v %s", err, out)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "sm.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close() // the socket file stays, with no one behind it
	if out, err := smProc(t, dir, config, "down").CombinedOutput(); err != nil {
		t.Errorf("down with a stale socket: %v %s", err, out)
	}
}
