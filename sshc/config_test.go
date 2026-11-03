// SPDX-License-Identifier: LGPL-3.0-or-later

package sshc

import (
	"strings"
	"testing"
)

func TestConfigUser(t *testing.T) {
	const conf = `# comment
Host desk desk.mesh.internal
    User root
Host *.example.com !bad.example.com
    user = "web user"
Match host foo exec "true"
    User matched
Host remote-*
    User=r1user
Host *
    User alice
    User ignored
`
	for host, want := range map[string]string{
		"desk":               "root",
		"Desk.Mesh.Internal": "root",
		"x.example.com":      "web user",
		"bad.example.com":    "alice", // negated, falls to Host *
		"remote-01":          "r1user",
		"remote-02":          "r1user",
		"remote":             "alice", // remote-* needs the dash
		"foo":                "alice", // Match blocks other than all are skipped
		"phone":              "alice",
	} {
		if got, err := ConfigUser(strings.NewReader(conf), host); err != nil || got != want {
			t.Errorf("ConfigUser(%q) = %q, %v; want %q", host, got, err, want)
		}
	}
	// A phone's Termux config, and lines before any Host.
	if u, _ := ConfigUser(strings.NewReader("Host *\n    User alice\n    IdentityFile ~/.ssh/id_ed25519_alice\n"), "remote-01"); u != "alice" {
		t.Errorf("Termux config: %q", u)
	}
	if u, _ := ConfigUser(strings.NewReader("User global\nHost x\n User other\n"), "y"); u != "global" {
		t.Errorf("global User: %q", u)
	}
	if u, _ := ConfigUser(strings.NewReader("Host x\n User other\n"), "y"); u != "" {
		t.Errorf("no match: %q", u)
	}
	for p, s := range map[string]string{"*": "", "a*c": "abbc", "a?c": "abc", "*.mesh.*": "x.mesh.internal"} {
		if !glob(p, s) {
			t.Errorf("glob(%q, %q) false", p, s)
		}
	}
	for p, s := range map[string]string{"a?c": "ac", "a*c": "abd", "desk": "desk0"} {
		if glob(p, s) {
			t.Errorf("glob(%q, %q) true", p, s)
		}
	}
}
