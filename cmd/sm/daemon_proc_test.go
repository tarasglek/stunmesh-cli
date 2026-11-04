// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

// With $SM_TEST_EXEC=1 the test binary is sm, so the tests can run sm as
// processes, and sm can start its daemon from os.Executable.
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

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func fill(b byte) (k [32]byte) {
	for i := range k {
		k[i] = b
	}
	return k
}

// sm processes against a real node: pb runs in this test, pa is sm's,
// its daemon a process. Two clients at once start one daemon and share
// it; sm down stops it; one killed leaves its socket, and the next client
// replaces it; a daemon with no clients exits after -idle.
func TestDaemonProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("runs sm processes and a WireGuard node")
	}
	privA, privB := fill(1), fill(2)
	portA, portB := freeUDPPort(t), freeUDPPort(t)
	cfgB, err := mesh.ParseConfig(procConfig("pb", 1, portB, portA, mesh.PublicKey(privA)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := mesh.Start(cfgB, privB, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	ln, err := b.ListenTCP(22)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				msg, _ := io.ReadAll(c)
				_, _ = c.Write(append([]byte("got "), msg...))
			}()
		}
	}()

	dir := t.TempDir()
	cfgA := filepath.Join(dir, "pa.json")
	if err := os.WriteFile(cfgA, procConfig("pa", 0, portA, portB, mesh.PublicKey(privB)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key"), []byte(mesh.FormatKey(privA)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "sm.sock")
	sm := func(args ...string) *exec.Cmd { return smProc(t, dir, cfgA, args...) }
	nc := func(msg string) {
		t.Helper()
		c := sm("nc", "pb", "22")
		c.Stdin = strings.NewReader(msg)
		var errb strings.Builder
		c.Stderr = &errb
		out, err := c.Output()
		if err != nil || string(out) != "got "+msg {
			t.Errorf("nc %q: %q, %v %s", msg, out, err, errb.String())
		}
	}
	down := func() {
		t.Helper()
		if out, err := sm("down").CombinedOutput(); err != nil {
			t.Fatalf("sm down: %v %s", err, out)
		}
		if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("socket after sm down: %v", err)
		}
	}
	defer sm("down").Run()

	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() { nc(fmt.Sprintf("client %d", i)) })
	}
	wg.Wait()
	log, _ := os.ReadFile(filepath.Join(dir, "sm.log"))
	if n := strings.Count(string(log), "sm daemon: serving"); n != 1 {
		t.Errorf("%d daemons served:\n%s", n, log)
	}
	nc("warm")
	down()

	// A daemon killed outright leaves its socket behind.
	d := sm("daemon")
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the daemon's socket", func() bool { _, err := os.Stat(sock); return err == nil })
	d.Process.Kill()
	d.Wait()
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("no stale socket to recover from: %v", err)
	}
	nc("after a crash")
	down()

	d = sm("daemon", "-idle", "500ms")
	var derr strings.Builder
	d.Stderr = &derr
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the daemon's socket", func() bool { _, err := os.Stat(sock); return err == nil })
	nc("before idle")
	exited := make(chan error, 1)
	go func() { exited <- d.Wait() }()
	select {
	case err := <-exited:
		if err != nil {
			t.Errorf("idle daemon: %v %s", err, derr.String())
		}
	case <-time.After(10 * time.Second):
		d.Process.Kill()
		t.Fatal("daemon did not exit when idle")
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket after idle exit: %v", err)
	}
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

// The applet that starts the daemon waits for its report, not for every
// holder of the report pipe: here a shell plugin that the node's first
// discovery cycle starts at once and that runs for a minute.
func TestDaemonPluginChild(t *testing.T) {
	if testing.Short() {
		t.Skip("runs sm processes")
	}
	dir := t.TempDir()
	var doc map[string]any
	_ = json.Unmarshal(procConfig("pa", 0, freeUDPPort(t), freeUDPPort(t), mesh.PublicKey(fill(2))), &doc)
	pids := filepath.Join(dir, "pids")
	doc["plugins"] = []any{map[string]any{"instance": "sh", "type": "shell", "config": map[string]any{"command": "/bin/sh", "args": []string{"-c", "echo $$ >>" + pids + "; exec sleep 60"}}}}
	defer func() { // the plugins outlive the daemon
		b, _ := os.ReadFile(pids)
		for _, f := range strings.Fields(string(b)) {
			if n, err := strconv.Atoi(f); err == nil {
				syscall.Kill(n, syscall.SIGKILL)
			}
		}
	}()
	doc["peers"].([]any)[0].(map[string]any)["plugin"] = "sh"
	doc["stun"] = map[string]any{"addresses": []string{}} // no wait for STUN: straight to the plugin
	b, _ := json.Marshal(doc)
	config := filepath.Join(dir, "pa.json")
	if err := os.WriteFile(config, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key"), []byte(mesh.FormatKey(fill(1))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer smProc(t, dir, config, "down").Run()
	for i := range 3 { // once to start the daemon, then against it
		start := time.Now()
		c := smProc(t, dir, config, "status", "-w", "100ms")
		done := make(chan error, 1)
		go func() { done <- c.Run() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("status %d: %v", i, err)
			}
		case <-time.After(10 * time.Second):
			c.Process.Kill()
			t.Fatalf("status %d still waiting after %v", i, time.Since(start))
		}
		time.Sleep(200 * time.Millisecond)
	}
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

// startDaemon returns once the daemon has reported, even if a child of
// the daemon still holds the report pipe.
func TestStartDaemonReadsReport(t *testing.T) {
	dir := t.TempDir()
	exe, pid := filepath.Join(dir, "sm"), filepath.Join(dir, "pid")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nsleep 60 &\necho $! >"+pid+"\necho ok >&3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if b, err := os.ReadFile(pid); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				syscall.Kill(n, syscall.SIGKILL)
			}
		}
	}()
	start := time.Now()
	r, err := startDaemon(exe, "", "log")
	if err != nil || r != "ok" {
		t.Errorf("startDaemon = %q, %v", r, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("startDaemon waited %v for the pipe's last holder", d)
	}
}
