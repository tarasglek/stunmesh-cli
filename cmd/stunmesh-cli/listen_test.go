// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
)

func TestParseListen(t *testing.T) {
	fs, err := parseListen([]string{"22:127.0.0.1:22", "8080:remote-01:80", "80:[fd00::5]:80"})
	if err != nil || len(fs) != 3 || fs[0].Port != 22 || fs[0].Target() != "127.0.0.1:22" || fs[1].Target() != "remote-01:80" || fs[2].Target() != "[fd00::5]:80" {
		t.Fatalf("parseListen = %+v, %v", fs, err)
	}
	for _, args := range [][]string{nil, {"22"}, {"0:127.0.0.1:22"}, {"10.200.0.8:22:127.0.0.1:22"}, {"22:127.0.0.1:0"},
		{"localhost:22:127.0.0.1:22"}, {"*:22:127.0.0.1:22"}, {":22:127.0.0.1:22"}} {
		if fs, err := parseListen(args); err == nil {
			t.Errorf("parseListen(%q) = %+v, want error", args, fs)
		}
	}
}

func TestListenRejects(t *testing.T) {
	env := map[string]string{"config": testConfig, "STUNMESH_CLI_KEY": t.TempDir() + "/key"}
	if code, _, errs := runEnv(env, "stunmesh-cli", "listen"); code != 2 || !strings.Contains(errs, "usage") {
		t.Errorf("listen: %d %q", code, errs)
	}
	if code, _, errs := runEnv(env, "stunmesh-cli", "listen", "22:127.0.0.1:22"); code != 1 || !strings.Contains(errs, "keygen") {
		t.Errorf("listen without a key: %d %q", code, errs)
	}
}
