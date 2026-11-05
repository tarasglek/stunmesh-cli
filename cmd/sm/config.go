// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

func nodeConfig(p proc) (mesh.Config, error) {
	b, err := p.config()
	if err != nil {
		return mesh.Config{}, err
	}
	return mesh.ParseConfig(b)
}

// startMesh brings this device's node up. $STUNMESH_CLI_LOG=debug, info,
// warn or error shows its log at that level and above on stderr; without
// it, verbose 1 shows info and 2 or more debug, as ssh -v and -vv.
func startMesh(p proc, cfg mesh.Config, verbose int) (*mesh.Mesh, error) {
	priv, err := loadKey(p)
	if err != nil {
		return nil, err
	}
	return mesh.Start(cfg, priv, logger(p, verbose))
}

// loadKey reads this device's private key.
func loadKey(p proc) ([32]byte, error) {
	path, err := keyPath(p.getenv)
	if err != nil {
		return [32]byte{}, err
	}
	priv, err := readKey(path)
	if errors.Is(err, fs.ErrNotExist) {
		return priv, fmt.Errorf("no key at %s; run %s keygen", path, self)
	}
	return priv, err
}

var logLevels = map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3}

func logger(p proc, verbose int) mesh.Logger {
	level := strings.ToLower(p.getenv("STUNMESH_CLI_LOG"))
	if level == "" && verbose > 0 {
		level = map[bool]string{true: "debug", false: "info"}[verbose > 1]
	}
	min, ok := logLevels[level]
	if !ok {
		return nil
	}
	return func(level, msg string) {
		if l, ok := logLevels[level]; !ok || l >= min {
			fmt.Fprintf(p.err, "%s: %s: %s\n", self, level, msg)
		}
	}
}
