// SPDX-License-Identifier: LGPL-3.0-or-later

package moshc

import (
	"strings"
	"testing"
)

func TestServerCommand(t *testing.T) {
	if got := ServerCommand(nil); got != "mosh-server new -s -c 256 -l LANG=C.UTF-8" {
		t.Errorf("login shell = %q", got)
	}
	got := ServerCommand([]string{"tmux", "new", "-s", "it's"})
	if want := `mosh-server new -s -c 256 -l LANG=C.UTF-8 -- 'tmux' 'new' '-s' 'it'\''s'`; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestParseConnect(t *testing.T) {
	const key = "AAAAAAAAAAAAAAAAAAAAAA"
	port, k, err := ParseConnect("Welcome to remote-02\r\n\r\nMOSH CONNECT 60001 " + key + "\r\n\nmosh-server (mosh 1.3.2)\n")
	if err != nil || port != 60001 || k != key {
		t.Errorf("ParseConnect = %d %q %v", port, k, err)
	}
	for name, out := range map[string]string{
		"none":       "mosh-server: command not found\n",
		"twice":      "MOSH CONNECT 1 " + key + "\nMOSH CONNECT 2 " + key + "\n",
		"short key":  "MOSH CONNECT 60001 AAAA\n",
		"padded key": "MOSH CONNECT 60001 " + key + "==\n",
		"bad port":   "MOSH CONNECT 0 " + key + "\n",
		"big port":   "MOSH CONNECT 70000 " + key + "\n",
		"extra":      "MOSH CONNECT 60001 " + key + " x\n",
	} {
		if _, _, err := ParseConnect(out); err == nil {
			t.Errorf("%s: accepted %q", name, out)
		}
	}
	if _, _, err := ParseConnect("bash: mosh-server: command not found"); err == nil || !strings.Contains(err.Error(), "command not found") {
		t.Errorf("error should carry the output: %v", err)
	}
}
