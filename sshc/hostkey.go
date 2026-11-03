// SPDX-License-Identifier: LGPL-3.0-or-later

package sshc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeys checks server keys against known_hosts files, as OpenSSH with
// StrictHostKeyChecking=ask does: a known key passes, a changed one fails,
// and an unknown host passes only if confirm accepts its key, which is
// then appended, hashed, to the first file. A nil confirm refuses unknown
// hosts. Files that do not exist yet count as empty. aliases are other
// host:port names the same host is known by, such as its full mesh name
// when the user typed the short one: a key known under any name passes,
// a different key known under any name is a changed key, and only a host
// known under none is unknown.
func HostKeys(files []string, confirm func(host string, key ssh.PublicKey) bool, aliases ...string) (ssh.HostKeyCallback, error) {
	if len(files) == 0 {
		return nil, errors.New("no known_hosts file")
	}
	check, err := newChecker(files)
	if err != nil {
		return nil, err
	}
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		var changed *knownhosts.KeyError
		for _, name := range append([]string{host}, aliases...) {
			err := check(name, remote, key)
			var ke *knownhosts.KeyError
			switch {
			case err == nil:
				return nil
			case !errors.As(err, &ke):
				return err
			case len(ke.Want) > 0 && changed == nil:
				changed = ke
			}
		}
		if changed != nil {
			return fmt.Errorf("host key for %s has CHANGED (%s %s); refusing: if this is expected, remove the old key from %s",
				host, key.Type(), ssh.FingerprintSHA256(key), changed.Want[0].Filename)
		}
		if confirm == nil || !confirm(host, key) {
			return fmt.Errorf("host key for %s (%s %s) is not known", host, key.Type(), ssh.FingerprintSHA256(key))
		}
		return appendKnown(files[0], host, key)
	}, nil
}

// newChecker is knownhosts over the files that exist; with none, every
// host is unknown.
func newChecker(files []string) (ssh.HostKeyCallback, error) {
	var existing []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			existing = append(existing, f)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	if len(existing) == 0 {
		return func(string, net.Addr, ssh.PublicKey) error { return &knownhosts.KeyError{} }, nil
	}
	return knownhosts.New(existing...)
}

func appendKnown(file, host string, key ssh.PublicKey) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	line := knownhosts.Line([]string{knownhosts.HashHostname(knownhosts.Normalize(host))}, key)
	if _, err := fmt.Fprintln(f, line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// KnownAlgorithms is ClientConfig.HostKeyAlgorithms for host: the
// algorithms for the key types known_hosts already holds for it first,
// then x/crypto's defaults. Without the known types first, x/crypto takes
// whichever key the server offers first, say ecdsa, and a host known by
// its ed25519 key looks like one whose key changed; OpenSSH prefers the
// known types the same way. The defaults after them keep a server that no
// longer has a known type negotiable, so a rotated key is reported as
// changed by HostKeys rather than as no common algorithm. Nil for an
// unknown host leaves the defaults. aliases are as for HostKeys.
func KnownAlgorithms(files []string, host string, remote net.Addr, aliases ...string) ([]string, error) {
	check, err := newChecker(files)
	if err != nil {
		return nil, err
	}
	var algos []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			algos = append(algos, a)
		}
	}
	for _, name := range append([]string{host}, aliases...) {
		// A key no entry has: the error lists every known key for the name.
		var ke *knownhosts.KeyError
		if !errors.As(check(name, remote, probeKey{}), &ke) {
			continue
		}
		for _, k := range ke.Want {
			for _, a := range algorithmsFor(k.Key.Type()) {
				add(a)
			}
		}
	}
	if len(algos) == 0 {
		return nil, nil
	}
	for _, a := range ssh.SupportedAlgorithms().HostKeys {
		add(a)
	}
	return algos, nil
}

// algorithmsFor maps a key type to the signature algorithms that verify
// it: RSA keys sign with SHA-2 too.
func algorithmsFor(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// probeKey matches no known_hosts entry.
type probeKey struct{}

func (probeKey) Type() string                        { return "stunmesh-cli-probe" }
func (probeKey) Marshal() []byte                     { return []byte("stunmesh-cli-probe") }
func (probeKey) Verify([]byte, *ssh.Signature) error { return errors.New("probe key") }
