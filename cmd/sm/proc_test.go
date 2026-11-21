// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

// With $SM_TEST_EXEC=1 the test binary is sm, so the tests can run sm as
// processes.
func TestMain(m *testing.M) {
	if os.Getenv("SM_TEST_EXEC") == "1" {
		os.Exit(osMain())
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

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func fill(b byte) (k [32]byte) {
	for i := range k {
		k[i] = b
	}
	return k
}

// sm nc as ssh runs it, against a real node pb in this test: its session
// works; with --expose, pb reaches a service on this host's loopback
// through it; a second sm nc on the device is refused at once and leaves
// the first alone; at stdin's EOF the first exits, its exposure goes with
// it and the port starts a node again.
func TestNcProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("runs sm processes and a WireGuard node")
	}
	privA, privB := fill(1), fill(2)
	portA, portB := freePort(t, "udp"), freePort(t, "udp")
	cfgB, err := mesh.ParseConfig(procConfig("pb", 1, portB, portA, mesh.PublicKey(privA)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := mesh.Start(cfgB, privB, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	echo, err := b.ListenTCP(22)
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	// The service to expose, on this host's loopback, as MagiskSSH's sshd.
	svc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	go func() {
		for {
			c, err := svc.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "sshd\n")
			c.Close()
		}
	}()
	exposed := strconv.Itoa(svc.Addr().(*net.TCPAddr).Port)

	dir := t.TempDir()
	cfgA := filepath.Join(dir, "pa.json")
	if err := os.WriteFile(cfgA, procConfig("pa", 0, portA, portB, mesh.PublicKey(privB)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key"), []byte(mesh.FormatKey(privA)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	first := smProc(t, dir, "--config", cfgA, "--expose", exposed, "nc", "pb", "22")
	in, err := first.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outPipe, err := first.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var firstErr strings.Builder
	first.Stderr = &firstErr
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- first.Wait() }()
	defer first.Process.Kill()
	out := bufio.NewReader(outPipe)
	roundTrip := func(msg string) {
		t.Helper()
		if _, err := io.WriteString(in, msg+"\n"); err != nil {
			t.Fatal(err)
		}
		if got, err := out.ReadString('\n'); err != nil || got != msg+"\n" {
			t.Fatalf("echo of %q = %q, %v; sm: %s", msg, got, err, firstErr.String())
		}
	}
	roundTrip("hello")

	reach := func(timeout time.Duration) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c, err := b.DialTCP(ctx, "pa", uint16(svc.Addr().(*net.TCPAddr).Port))
		if err != nil {
			return "", err
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		line, err := bufio.NewReader(c).ReadString('\n')
		return line, err
	}
	if got, err := reach(10 * time.Second); err != nil || got != "sshd\n" {
		t.Fatalf("exposed port from pb: %q, %v; sm: %s", got, err, firstErr.String())
	}

	start := time.Now()
	second := smProc(t, dir, "--config", cfgA, "nc", "pb", "22")
	second.Stdin = strings.NewReader("")
	msg, err := second.CombinedOutput()
	if err == nil || !strings.Contains(string(msg), "already running") || time.Since(start) > 5*time.Second {
		t.Errorf("second sm nc: %v after %v: %s", err, time.Since(start), msg)
	}
	roundTrip("still here")

	in.Close()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("sm nc did not exit at stdin's EOF")
	}
	if got, err := reach(2 * time.Second); err == nil {
		t.Errorf("exposed port after sm nc exited: %q", got)
	}

	third := smProc(t, dir, "--config", cfgA, "nc", "pb", "22")
	third.Stdin = strings.NewReader("")
	if msg, err := third.CombinedOutput(); err != nil {
		t.Errorf("sm nc after the first exited: %v %s", err, msg)
	}
}

// smProc runs the test binary as sm with dir/key as its key.
func smProc(t *testing.T, dir string, args ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(exe)
	c.Args = append([]string{"sm"}, args...)
	c.Env = append(os.Environ(), "SM_TEST_EXEC=1", "STUNMESH_CLI_KEY="+filepath.Join(dir, "key"))
	return c
}
