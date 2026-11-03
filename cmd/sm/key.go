// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

// keyDir is the key's directory under the config directory. It keeps
// the project's name, not the command's, so a key outlives a rename.
const keyDir = "stunmesh-cli"

// keyPath is where this device's private key lives: $STUNMESH_CLI_KEY, or
// stunmesh-cli/key under $XDG_CONFIG_HOME, or under ~/.config.
func keyPath(getenv func(string) string) (string, error) {
	if p := getenv("STUNMESH_CLI_KEY"); p != "" {
		return p, nil
	}
	dir := getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home := getenv("HOME")
		if home == "" {
			return "", errors.New("no HOME, XDG_CONFIG_HOME or STUNMESH_CLI_KEY to find the key in")
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, keyDir, "key"), nil
}

// readKey loads the key, refusing it, as ssh refuses a private key, when
// others can read it.
func readKey(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return [32]byte{}, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return [32]byte{}, fmt.Errorf("%s: mode %v lets others read the key; chmod 600 it", path, st.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, 256))
	if err != nil {
		return [32]byte{}, err
	}
	k, err := mesh.ParseKey(string(b))
	if err != nil {
		return [32]byte{}, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// createKey writes a new key to path, never over an existing one, making
// its directory 0700 if missing. ownDir says the directory is ours, the
// default stunmesh-cli one, so an existing one is tightened to 0700 too and
// the key's existence stays private; a directory $STUNMESH_CLI_KEY points
// into, such as /tmp, is the caller's and left alone.
func createKey(path string, ownDir bool, rand io.Reader) ([32]byte, error) {
	k, err := mesh.GenerateKey(rand)
	if err != nil {
		return k, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return k, err
	}
	if ownDir {
		if err := os.Chmod(dir, 0o700); err != nil {
			return k, err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return k, err
	}
	if _, err := fmt.Fprintln(f, mesh.FormatKey(k)); err != nil {
		f.Close()
		return k, err
	}
	return k, f.Close()
}

// keygen makes this device's key if it has none and prints its public key,
// the value for the node's pubkey in mesh.yaml. Run again, it only prints.
func keygen(args []string, p proc) int {
	if len(args) != 0 {
		fmt.Fprintf(p.err, "usage: %s keygen\n", self)
		return 2
	}
	path, err := keyPath(p.getenv)
	if err != nil {
		return fail(p, "keygen", err)
	}
	k, err := readKey(path)
	switch {
	case err == nil:
		fmt.Fprintf(p.err, "%s exists; its public key:\n", path)
	case errors.Is(err, fs.ErrNotExist):
		if k, err = createKey(path, p.getenv("STUNMESH_CLI_KEY") == "", p.rand); err != nil {
			return fail(p, "keygen", err)
		}
		fmt.Fprintf(p.err, "wrote %s; put this public key in mesh.yaml as the node's pubkey:\n", path)
	default:
		return fail(p, "keygen", err)
	}
	fmt.Fprintln(p.out, mesh.FormatKey(mesh.PublicKey(k)))
	return 0
}
