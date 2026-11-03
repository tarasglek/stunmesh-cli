// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

// config/ holds node.json when make build NODE=... put one there.
//
//go:embed config
var configFS embed.FS

func embeddedConfig() ([]byte, error) { return readConfig(configFS) }

func readConfig(fsys fs.FS) ([]byte, error) {
	b, err := fs.ReadFile(fsys, "config/node.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("no node config compiled in; build with make build NODE=<node> CONFIG=<dir of mesh.yaml>")
	}
	return b, err
}

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
	path, err := keyPath(p.getenv)
	if err != nil {
		return nil, err
	}
	priv, err := readKey(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no key at %s; run %s keygen", path, self)
	}
	if err != nil {
		return nil, err
	}
	return mesh.Start(cfg, priv, logger(p, verbose))
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
