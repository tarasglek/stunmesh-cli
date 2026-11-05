// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

// A node's config travels inside its binary as a zip appended to the
// executable, as self-extracting archives were made: one generic build per
// architecture, and any copy of it can carry any node's config. The zip's
// offsets count from the start of the file, so unzip -p sm node.json reads
// it as is, and the entry is stored, not compressed, so it shows as plain
// text at the end of the file too. Only the device's private key lives
// outside the binary. The ssh_config stunmesh-avahi's gen.py renders next
// to node.json travels too, so sm config ssh can print it.
const (
	attachedName = "node.json"
	sshName      = "ssh_config"
)

var errNoConfig = errors.New("no node config: attach one with sm config attach, or give one with --config FILE or $STUNMESH_CLI_CONFIG")

// attachedStart finds a zip appended to the file r of size bytes, from
// its end of central directory record, and returns where its lowest local
// header starts, which is where the executable ends. Every central
// directory entry must lie inside the file, start with its signature and
// point below the directory; a tail that fails any check is not ours.
func attachedStart(r io.ReaderAt, size int64) (int64, bool) {
	const eocdLen, cdhLen = 22, 46
	n := min(size, eocdLen+0xffff)
	if n < eocdLen {
		return 0, false
	}
	tail := make([]byte, n)
	if _, err := r.ReadAt(tail, size-n); err != nil {
		return 0, false
	}
	for i := len(tail) - eocdLen; i >= 0; i-- {
		e := tail[i:]
		if binary.LittleEndian.Uint32(e) != 0x06054b50 || i+eocdLen+int(binary.LittleEndian.Uint16(e[20:])) != len(tail) {
			continue
		}
		entries := int(binary.LittleEndian.Uint16(e[10:]))
		cdSize := int64(binary.LittleEndian.Uint32(e[12:]))
		cd := int64(binary.LittleEndian.Uint32(e[16:]))
		if entries == 0 || cd+cdSize > size-int64(len(tail)-i) || cdSize > 1<<20 {
			continue
		}
		dir := make([]byte, cdSize)
		if _, err := r.ReadAt(dir, cd); err != nil {
			continue
		}
		start, ok := cd, true
		for k, off := 0, 0; k < entries; k++ {
			if off+cdhLen > len(dir) || binary.LittleEndian.Uint32(dir[off:]) != 0x02014b50 {
				ok = false
				break
			}
			h := dir[off:]
			start = min(start, int64(binary.LittleEndian.Uint32(h[42:])))
			off += cdhLen + int(binary.LittleEndian.Uint16(h[28:])) + int(binary.LittleEndian.Uint16(h[30:])) + int(binary.LittleEndian.Uint16(h[32:]))
		}
		if ok {
			return start, true
		}
	}
	return 0, false
}

// readAttached reads the file name attached to the executable at path.
func readAttached(path, name string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if _, ok := attachedStart(f, st.Size()); !ok {
		return nil, errNoConfig
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return nil, fmt.Errorf("attached config: %w", err)
	}
	rc, err := zr.Open(name)
	if err != nil {
		return nil, fmt.Errorf("attached config: %w", err)
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 1<<20))
}

// attach writes to out the executable at base, without any config it
// carries, with config attached, and the ssh_config next to it, if any.
// The config is checked first, so a broken one, or one with a private
// key, never ships. The zip is the same bytes for the same input.
func attach(base, config, out string) error {
	exe, err := os.ReadFile(base)
	if err != nil {
		return err
	}
	if start, ok := attachedStart(bytes.NewReader(exe), int64(len(exe))); ok {
		exe = exe[:start]
	}
	js, err := os.ReadFile(config)
	if err != nil {
		return err
	}
	if _, err := mesh.ParseConfig(js); err != nil {
		return fmt.Errorf("%s: %w", config, err)
	}
	files := [][2]string{{attachedName, string(js)}}
	ssh, err := os.ReadFile(filepath.Join(filepath.Dir(config), sshName))
	if err == nil {
		files = append(files, [2]string{sshName, string(ssh)})
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var buf bytes.Buffer
	buf.Write(exe)
	zw := zip.NewWriter(&buf)
	zw.SetOffset(int64(len(exe)))
	for _, f := range files {
		w, err := zw.CreateRaw(&zip.FileHeader{
			Name: f[0], Method: zip.Store,
			// 1980-01-01, the first MS-DOS date, for reproducible bytes;
			// CreateRaw takes the DOS fields as they are.
			ModifiedDate:     1<<5 | 1,
			CRC32:            crc32.ChecksumIEEE([]byte(f[1])),
			CompressedSize64: uint64(len(f[1])), UncompressedSize64: uint64(len(f[1])),
		})
		if err != nil {
			return err
		}
		if _, err := io.WriteString(w, f[1]); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(out), "."+filepath.Base(out)+".tmp")
	if err := os.WriteFile(tmp, buf.Bytes(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}

// configSource is where the attached file name, node.json or ssh_config,
// comes from: the file of that name beside the node config path, given
// by --config or $STUNMESH_CLI_CONFIG, else the executable's attachment.
func configSource(path, name string, exe func() (string, error)) func() ([]byte, error) {
	if path != "" {
		if name != attachedName {
			path = filepath.Join(filepath.Dir(path), name)
		}
		return func() ([]byte, error) { return os.ReadFile(path) }
	}
	return func() ([]byte, error) {
		p, err := exe()
		if err != nil {
			return nil, err
		}
		return readAttached(p, name)
	}
}

// configApplet prints the node config in use or the ssh_config that came
// with it, or attaches one to a copy of a binary: sm config attach BINARY
// NODE.json OUT.
func configApplet(args []string, p proc) int {
	switch {
	case len(args) == 0:
		b, err := p.config()
		if err != nil {
			return fail(p, "config", err)
		}
		p.out.Write(b)
		return 0
	case args[0] == "ssh" && len(args) == 1:
		b, err := p.sshConfig()
		if errors.Is(err, fs.ErrNotExist) {
			err = errors.New("no ssh_config came with the node config; gen.py renders one next to node.json")
		}
		if err != nil {
			return fail(p, "config", err)
		}
		p.out.Write(b)
		return 0
	case args[0] == "attach" && len(args) == 4:
		if err := attach(args[1], args[2], args[3]); err != nil {
			return fail(p, "config", err)
		}
		return 0
	}
	fmt.Fprintf(p.err, "usage: %s config                          print the node config in use\n       %s config ssh                      print the ssh_config that came with it\n       %s config attach BINARY NODE.json OUT   copy BINARY to OUT carrying NODE.json and the ssh_config beside it\n", self, self, self)
	return 2
}
