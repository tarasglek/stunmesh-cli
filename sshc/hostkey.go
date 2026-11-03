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
// hosts. Files that do not exist yet count as empty.
func HostKeys(files []string, confirm func(host string, key ssh.PublicKey) bool) (ssh.HostKeyCallback, error) {
	if len(files) == 0 {
		return nil, errors.New("no known_hosts file")
	}
	var existing []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			existing = append(existing, f)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	check := func(string, net.Addr, ssh.PublicKey) error { return &knownhosts.KeyError{} }
	if len(existing) > 0 {
		var err error
		if check, err = knownhosts.New(existing...); err != nil {
			return nil, err
		}
	}
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := check(host, remote, key)
		var ke *knownhosts.KeyError
		if !errors.As(err, &ke) {
			return err
		}
		if len(ke.Want) > 0 {
			return fmt.Errorf("host key for %s has CHANGED (%s %s); refusing: if this is expected, remove the old key from %s",
				host, key.Type(), ssh.FingerprintSHA256(key), ke.Want[0].Filename)
		}
		if confirm == nil || !confirm(host, key) {
			return fmt.Errorf("host key for %s (%s %s) is not known", host, key.Type(), ssh.FingerprintSHA256(key))
		}
		return appendKnown(files[0], host, key)
	}, nil
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
// unknown host leaves the defaults.
func KnownAlgorithms(files []string, host string, remote net.Addr) ([]string, error) {
	var existing []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			existing = append(existing, f)
		}
	}
	if len(existing) == 0 {
		return nil, nil
	}
	check, err := knownhosts.New(existing...)
	if err != nil {
		return nil, err
	}
	// A key no entry has: the error lists every known key for the host.
	err = check(host, remote, probeKey{})
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		return nil, nil
	}
	var algos []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			algos = append(algos, a)
		}
	}
	for _, k := range ke.Want {
		for _, a := range algorithmsFor(k.Key.Type()) {
			add(a)
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
