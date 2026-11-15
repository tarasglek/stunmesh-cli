// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeExe is a stand-in executable, with a stray end-of-central-directory
// signature inside, as compressed data in a real binary may have.
func fakeExe(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	b := append(bytes.Repeat([]byte("\x7fELF code "), 4000), []byte("PK\x05\x06 not a zip")...)
	b = append(b, bytes.Repeat([]byte{0}, 100)...)
	p := filepath.Join(dir, "sm")
	if err := os.WriteFile(p, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return p, b
}

func TestAttach(t *testing.T) {
	dir := t.TempDir()
	base, exe := fakeExe(t, dir)
	if _, err := readAttached(base); err != errNoConfig {
		t.Fatalf("plain executable: %v", err)
	}
	conf := filepath.Join(dir, "node.json")
	os.WriteFile(conf, []byte(testConfig), 0o600)
	out := filepath.Join(dir, "sm-node")
	if err := attach(base, conf, out); err != nil {
		t.Fatal(err)
	}
	got, err := readAttached(out)
	if err != nil || string(got) != testConfig {
		t.Fatalf("readAttached = %q, %v", got, err)
	}
	if zr, err := zip.OpenReader(out); err == nil {
		if m := zr.File[0].Method; m != zip.Store {
			t.Errorf("entry method %d, want stored", m)
		}
		zr.Close()
	}
	b, _ := os.ReadFile(out)
	if !bytes.HasPrefix(b, exe) || !bytes.Contains(b, []byte(testConfig)) {
		t.Error("the executable is not kept, or the config is not stored as plain text")
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	// Absolute offsets: Go's zip reader and unzip read the whole file as is.
	if zr, err := zip.OpenReader(out); err != nil || len(zr.File) != 1 || zr.File[0].Name != "node.json" {
		t.Errorf("zip.OpenReader: %v", err)
	} else {
		zr.Close()
	}
	if unzip, err := exec.LookPath("unzip"); err == nil {
		if o, err := exec.Command(unzip, "-p", out, "node.json").Output(); err != nil || string(o) != testConfig {
			t.Errorf("unzip -p: %q, %v", o, err)
		}
	}

	// Attaching again replaces the config; the result is byte-identical
	// to attaching to the plain executable, so it is reproducible.
	other := strings.Replace(testConfig, `"desk-cli"`, `"phone-cli"`, 1)
	os.WriteFile(conf, []byte(other), 0o600)
	again := filepath.Join(dir, "sm-again")
	if err := attach(out, conf, again); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(dir, "sm-fresh")
	attach(base, conf, fresh)
	a, _ := os.ReadFile(again)
	f, _ := os.ReadFile(fresh)
	if !bytes.Equal(a, f) {
		t.Error("re-attaching does not strip the old config")
	}
	if got, _ := readAttached(again); string(got) != other {
		t.Errorf("after re-attach: %q", got)
	}
}

// A config with a private key, or one that does not parse, never ships.
func TestAttachRefuses(t *testing.T) {
	dir := t.TempDir()
	base, _ := fakeExe(t, dir)
	for name, conf := range map[string]string{
		"private key": strings.Replace(testConfig, `"listen_port"`, `"private_key": "x", "listen_port"`, 1),
		"broken":      "{",
	} {
		p := filepath.Join(dir, "bad.json")
		os.WriteFile(p, []byte(conf), 0o600)
		if err := attach(base, p, filepath.Join(dir, "out")); err == nil {
			t.Errorf("%s: attached", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); err == nil {
		t.Error("output written for a refused config")
	}
}

// --config FILE and $STUNMESH_CLI_CONFIG read the config from the file
// system instead of the binary; sm config prints the one in use.
func TestConfigSource(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "node.json")
	os.WriteFile(conf, []byte(testConfig), 0o600)
	var out, errb bytes.Buffer
	p := testProc(nil, &out, &errb)
	base, _ := fakeExe(t, dir)
	p.config = configSource("", base)
	if code := run([]string{"sm", "config"}, p); code != 1 || !strings.Contains(errb.String(), "sm config attach") {
		t.Errorf("no config: %d %q", code, errb.String())
	}
	out.Reset()
	if code := run([]string{"sm", "--config", conf, "config"}, p); code != 0 || out.String() != testConfig {
		t.Errorf("--config: %d %q", code, out.String())
	}
	if code := run([]string{"sm", "--config"}, p); code != 2 {
		t.Errorf("--config without a file: %d", code)
	}
	if b, err := configSource(conf, "")(); err != nil || string(b) != testConfig {
		t.Errorf("file source: %v", err)
	}
}

// zipAfter is exe followed by a zip of the given entries, built with
// archive/zip at absolute offsets, and its comment.
func zipAfter(t *testing.T, exe []byte, comment string, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(exe)
	zw := zip.NewWriter(&buf)
	zw.SetOffset(int64(len(exe)))
	for _, n := range names {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("data of " + n))
	}
	zw.SetComment(comment)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Crafted tails: attachedStart finds where the executable ends or says
// there is no zip, and never reads past the file.
func TestAttachedStart(t *testing.T) {
	exe := bytes.Repeat([]byte("code"), 1000)
	two := zipAfter(t, exe, "", "a", "b")
	// Swap the two directory entries, so the first one listed is not the
	// lowest local header.
	eocd := bytes.LastIndex(two, []byte("PK\x05\x06"))
	cd := int(binary.LittleEndian.Uint32(two[eocd+16:]))
	first := 46 + 1 // fixed header plus the one-byte name "a"
	swapped := append([]byte(nil), two[:cd]...)
	swapped = append(swapped, two[cd+first:eocd]...)
	swapped = append(swapped, two[cd:cd+first]...)
	swapped = append(swapped, two[eocd:]...)
	past := zipAfter(t, exe, "", "a")
	binary.LittleEndian.PutUint32(past[len(past)-22+16:], uint32(len(past)+100))
	for _, tc := range []struct {
		name  string
		file  []byte
		start int64
		ok    bool
	}{
		{"no zip", exe, 0, false},
		{"empty file", nil, 0, false},
		{"one entry", zipAfter(t, exe, "", "a"), int64(len(exe)), true},
		{"comment", zipAfter(t, exe, "a comment", "a"), int64(len(exe)), true},
		{"two entries", two, int64(len(exe)), true},
		{"entries out of order", swapped, int64(len(exe)), true},
		{"directory past the end", past, 0, false},
		{"truncated", two[:len(two)-30], 0, false},
	} {
		start, ok := attachedStart(bytes.NewReader(tc.file), int64(len(tc.file)))
		if ok != tc.ok || (ok && start != tc.start) {
			t.Errorf("%s: %d, %v; want %d, %v", tc.name, start, ok, tc.start, tc.ok)
		}
	}
}

// readAttached reads at most 1 MiB of an entry.
func TestReadAttachedCap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sm")
	var buf bytes.Buffer
	buf.Write([]byte("code"))
	zw := zip.NewWriter(&buf)
	zw.SetOffset(4)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "node.json", Method: zip.Store})
	w.Write(bytes.Repeat([]byte("x"), 2<<20))
	zw.Close()
	os.WriteFile(p, buf.Bytes(), 0o755)
	if b, err := readAttached(p); err != nil || len(b) != 1<<20 {
		t.Errorf("read %d bytes, %v; want 1 MiB", len(b), err)
	}
}

// sm config ssh sends every other host through this very sm and config.
func TestConfigSSH(t *testing.T) {
	env := map[string]string{"config": testConfig}
	const hosts = "Host lap1 remote-01 *.mesh.internal\n    ProxyCommand "
	if code, out, errs := runEnv(env, "sm", "config", "ssh"); code != 0 || out != hosts+"/x/sm nc %h %p\n" {
		t.Errorf("config ssh: %d %q %q", code, out, errs)
	}
	var o, e bytes.Buffer
	p := testProc(env, &o, &e)
	p.exe, p.configFile = []string{"/linker64", "/x/sm"}, "/c/node.json"
	if code := run([]string{"sm", "config", "ssh"}, p); code != 0 || o.String() != hosts+"/linker64 /x/sm --config /c/node.json nc %h %p\n" {
		t.Errorf("config ssh through the linker: %d %q %q", code, o.String(), e.String())
	}
}
