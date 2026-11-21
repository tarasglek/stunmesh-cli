// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testConfig is a node config as gen.py renders it.
const testConfig = `{
  "name": "desk-cli",
  "interface": {"addresses": ["10.200.0.8/24"], "listen_port": 51820},
  "peers": [{"name": "remote-01", "public_key": "7NkaedCuhiw0u6VLDY1xm4ywp+eZLYUT643Ry53LF04=", "allowed_ips": ["10.200.0.5/32"]},
            {"name": "lap1", "public_key": "WB3BdFtSnifYp3B+mU0Wy5lN4+FevBQs6C+rk7/ouD0=", "allowed_ips": ["10.200.0.2/32"]}],
  "domain": "mesh.internal",
  "hosts": {"remote-01": "10.200.0.5", "lap1": "10.200.0.2", "desk-cli": "10.200.0.8"}
}`

// Through Android's linker, by hand or by termux-exec, sm sees the argv
// of a direct run by path, and runs again as the linker on the binary
// itself, not the symlink that named an applet.
func TestInvocation(t *testing.T) {
	const linker = "/apex/com.android.runtime/bin/linker64"
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	sm, mosh := filepath.Join(dir, "sm"), filepath.Join(dir, "mosh")
	os.WriteFile(sm, nil, 0o755)
	os.Symlink("sm", mosh)
	for _, tc := range []struct {
		exe       string
		argv      []string
		cmd, want []string
	}{
		{linker, []string{"/system/bin/linker64", sm, "nc", "h", "22"}, []string{linker, sm}, []string{sm, "nc", "h", "22"}},
		{linker, []string{"sm", sm, "--list"}, []string{linker, sm}, []string{sm, "--list"}},
		{linker, []string{"mosh", mosh, "h"}, []string{linker, sm}, []string{mosh, "h"}},
		{sm, []string{"mosh", "h"}, []string{sm}, []string{"mosh", "h"}}, // run directly
	} {
		if cmd, argv, err := invocation(tc.exe, tc.argv); err != nil || !slices.Equal(cmd, tc.cmd) || !slices.Equal(argv, tc.want) {
			t.Errorf("invocation(%q, %q) = %q %q %v, want %q %q", tc.exe, tc.argv, cmd, argv, err, tc.cmd, tc.want)
		}
	}
	if _, _, err := invocation(linker, []string{"sm", filepath.Join(dir, "gone")}); err == nil {
		t.Error("no error for a binary that is not there")
	}
}

func TestPick(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		name string
		args []string
	}{
		{[]string{"/x/build/bin/mosh", "desk"}, "mosh", []string{"desk"}},
		{[]string{"sm", "mosh", "desk"}, "mosh", []string{"desk"}},
		{[]string{"./build/sm", "nc", "desk", "22"}, "nc", []string{"desk", "22"}},
		{[]string{"build/sm-desk-cli-linux-amd64", "config"}, "config", nil},
		{[]string{"sm"}, "", nil},
		{[]string{"/usr/bin/stunmesh-cli", "nc"}, "stunmesh-cli", []string{"nc"}}, // any other name is an applet's
		{[]string{"smash", "x"}, "smash", []string{"x"}},                          // a prefix of sm- only
		{nil, "", nil},
	} {
		name, args := pick(tc.argv)
		if name != tc.name || !slices.Equal(args, tc.args) {
			t.Errorf("pick(%q) = %q %q, want %q %q", tc.argv, name, args, tc.name, tc.args)
		}
	}
}

// testProc is a process with environment env, no stdin and the node
// config in env["config"], if any.
func testProc(env map[string]string, out, errb *bytes.Buffer) proc {
	config := func() ([]byte, error) {
		if c, ok := env["config"]; ok {
			return []byte(c), nil
		}
		return nil, errNoConfig
	}
	return proc{
		in: strings.NewReader(""), out: out, err: errb,
		getenv: func(k string) string { return env[k] },
		rand:   rand.Reader, exe: []string{"/x/sm"}, config: config,
	}
}

func runEnv(env map[string]string, argv ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(argv, testProc(env, &out, &errb))
	return code, out.String(), errb.String()
}

func runCapture(argv ...string) (int, string, string) { return runEnv(nil, argv...) }

func TestRun(t *testing.T) {
	if code, out, _ := runCapture("sm", "--list"); code != 0 || out != "config\nkeygen\nmosh\nnc\n" {
		t.Errorf("--list: %d %q", code, out)
	}
	if code, out, _ := runCapture("sm", "--version"); code != 0 || !strings.HasPrefix(out, "sm ") {
		t.Errorf("--version: %d %q", code, out)
	}
	if code, _, errs := runCapture("sm", "nosuch"); code != 127 || !strings.Contains(errs, `unknown applet "nosuch"`) {
		t.Errorf("unknown applet: %d %q", code, errs)
	}
	if code, _, errs := runCapture("sm"); code != 127 || !strings.Contains(errs, "usage:") {
		t.Errorf("no applet: %d %q", code, errs)
	}
}

// --expose takes ports in 1-65535, any number of times, before the applet,
// mixed with --config; sm run again carries them on.
func TestExposeFlag(t *testing.T) {
	for _, args := range [][]string{{"--expose"}, {"--expose", "0", "config"}, {"--expose", "x", "config"}, {"--expose", "65536", "config"}, {"--expose", "22"}} {
		if code, _, errs := runEnv(map[string]string{"config": testConfig}, append([]string{"sm"}, args...)...); code != 2 || errs == "" {
			t.Errorf("%q: %d %q, want 2", args, code, errs)
		}
	}
	var out, errb bytes.Buffer
	p := testProc(map[string]string{"config": testConfig}, &out, &errb)
	p.exe = []string{"/linker64", "/x/sm"}
	conf := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(conf, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"sm", "--expose", "22", "--config", conf, "--expose", "8022", "config", "ssh"}, p); code != 0 {
		t.Fatalf("config ssh: %d %s", code, errb.String())
	}
	want := "ProxyCommand /linker64 /x/sm --config " + conf + " --expose 22 --expose 8022 nc %h %p\n"
	if !strings.HasSuffix(out.String(), want) {
		t.Errorf("config ssh ends %q, want %q", out.String()[strings.LastIndex(out.String()[:out.Len()-1], "\n")+1:], want)
	}
}
