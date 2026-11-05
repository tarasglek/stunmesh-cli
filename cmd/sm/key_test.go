// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

func TestKeyPath(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"STUNMESH_CLI_KEY": "/k", "HOME": "/h"}, "/k"},
		{map[string]string{"XDG_CONFIG_HOME": "/x", "HOME": "/h"}, "/x/stunmesh-cli/key"},
		{map[string]string{"HOME": "/h"}, "/h/.config/stunmesh-cli/key"},
	} {
		if got, err := keyPath(func(k string) string { return tc.env[k] }); err != nil || got != tc.want {
			t.Errorf("keyPath(%v) = %q, %v; want %q", tc.env, got, err, tc.want)
		}
	}
	if _, err := keyPath(func(string) string { return "" }); err == nil {
		t.Error("keyPath with no environment succeeded")
	}
}

// keygen creates a private 0600 key once and from then on prints the same
// public key without touching the file.
func TestKeygen(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{"XDG_CONFIG_HOME": dir}
	path := filepath.Join(dir, "stunmesh-cli", "key")

	code, pub, errs := runEnv(env, "sm", "keygen")
	if code != 0 || !strings.Contains(errs, "wrote "+path) {
		t.Fatalf("keygen: %d %q %q", code, pub, errs)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if d, _ := os.Stat(filepath.Dir(path)); d.Mode().Perm() != 0o700 {
		t.Errorf("key dir mode %v", d.Mode().Perm())
	}
	priv, err := readKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(pub) != mesh.FormatKey(mesh.PublicKey(priv)) {
		t.Errorf("printed %q, not the key's public key", pub)
	}
	if strings.Contains(pub+errs, mesh.FormatKey(priv)) {
		t.Error("keygen printed the private key")
	}

	before, _ := os.ReadFile(path)
	code, again, errs := runEnv(env, "sm", "keygen")
	after, _ := os.ReadFile(path)
	if code != 0 || again != pub || string(before) != string(after) || !strings.Contains(errs, "exists") {
		t.Errorf("second keygen: %d %q %q, file changed %v", code, again, errs, string(before) != string(after))
	}
}

// An existing default key directory readable by others is tightened; a
// directory $STUNMESH_CLI_KEY points into is the caller's and kept.
func TestKeygenDirMode(t *testing.T) {
	cfg := t.TempDir()
	own := filepath.Join(cfg, "stunmesh-cli")
	if err := os.Mkdir(own, 0o755); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := runEnv(map[string]string{"XDG_CONFIG_HOME": cfg}, "keygen"); code != 0 {
		t.Fatalf("keygen: %d %q", code, errs)
	}
	if st, _ := os.Stat(own); st.Mode().Perm() != 0o700 {
		t.Errorf("default key dir mode %v, want 0700", st.Mode().Perm())
	}

	shared := t.TempDir()
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := runEnv(map[string]string{"STUNMESH_CLI_KEY": filepath.Join(shared, "key")}, "keygen"); code != 0 {
		t.Fatalf("keygen: %d %q", code, errs)
	}
	if st, _ := os.Stat(shared); st.Mode().Perm() != 0o755 {
		t.Errorf("caller's dir mode changed to %v", st.Mode().Perm())
	}
}

func TestReadKeyRefusesReadableKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(mesh.FormatKey([32]byte{1})+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readKey(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("readKey of a 0644 key: %v", err)
	}
	if code, _, errs := runEnv(map[string]string{"STUNMESH_CLI_KEY": path}, "keygen"); code != 1 || !strings.Contains(errs, "chmod 600") {
		t.Errorf("keygen over a readable key: %d %q", code, errs)
	}
}
