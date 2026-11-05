// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/rand"
	"io/fs"
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

func TestPick(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		name string
		args []string
	}{
		{[]string{"/x/build/bin/mosh", "desk"}, "mosh", []string{"desk"}},
		{[]string{"sm", "mosh", "desk"}, "mosh", []string{"desk"}},
		{[]string{"./build/sm", "nc", "desk", "22"}, "nc", []string{"desk", "22"}},
		{[]string{"build/sm-desk-cli-amd64", "status"}, "status", nil},
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
		rand:   rand.Reader, config: config,
		sshConfig: func() ([]byte, error) {
			if c, ok := env["ssh_config"]; ok {
				return []byte(c), nil
			}
			return nil, fs.ErrNotExist
		},
	}
}

func runEnv(env map[string]string, argv ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(argv, testProc(env, &out, &errb))
	return code, out.String(), errb.String()
}

func runCapture(argv ...string) (int, string, string) { return runEnv(nil, argv...) }

func TestRun(t *testing.T) {
	if code, out, _ := runCapture("sm", "--list"); code != 0 || out != "config\nkeygen\nnc\nstatus\n" {
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
