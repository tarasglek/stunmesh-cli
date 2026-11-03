// SPDX-License-Identifier: LGPL-3.0-or-later

package sshc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Prompt asks the user for a secret or an answer; echo says whether the
// reply may be shown as typed. Nil means no one to ask.
type Prompt func(prompt string, echo bool) (string, error)

// Auth says where credentials come from, in OpenSSH's order: the agent,
// then identity files, then keyboard-interactive and password through
// Prompt.
type Auth struct {
	// AgentSock is $SSH_AUTH_SOCK; empty for no agent.
	AgentSock string
	// Identities are -i files, which must exist; Defaults, such as
	// ~/.ssh/id_ed25519, are used when present.
	Identities, Defaults []string
	Prompt               Prompt
	// Logf, if set, hears which keys are found and why any are skipped.
	Logf func(format string, args ...any)
}

func (a Auth) logf(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
	}
}

// Methods builds the auth methods. Like ssh, it reads identity files and
// asks for passphrases only when the server gets as far as trying them:
// after the host key is checked, and not at all when an agent key is
// accepted first. A missing -i file is still an error here, a usage error
// to report before any connection. close releases the agent connection.
func (a Auth) Methods() (methods []ssh.AuthMethod, close func(), err error) {
	close = func() {}
	for _, f := range a.Identities {
		if _, err := os.Stat(f); err != nil {
			return nil, close, err
		}
	}
	if a.AgentSock != "" {
		if conn, err := net.Dial("unix", a.AgentSock); err == nil {
			close = func() { conn.Close() }
			methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
			a.logf("agent %s: connected", a.AgentSock)
		} else {
			a.logf("agent: %v", err)
		}
	} else {
		a.logf("agent: no SSH_AUTH_SOCK")
	}
	var once sync.Once
	var signers []ssh.Signer
	var loadErr error
	methods = append(methods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		once.Do(func() { signers, loadErr = a.loadFiles() })
		return signers, loadErr
	}))
	if a.Prompt != nil {
		methods = append(methods,
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i, q := range questions {
					var err error
					if answers[i], err = a.Prompt(q, echos[i]); err != nil {
						return nil, err
					}
				}
				return answers, nil
			}),
			ssh.PasswordCallback(func() (string, error) { return a.Prompt("Password: ", false) }),
		)
	}
	return methods, close, nil
}

// loadFiles loads the -i identities, then the defaults that exist. A key
// that cannot be used, say one with a passphrase and no one to ask, is
// skipped as ssh skips it; only when none loads is the first failure
// returned, which ends authentication with its reason, since an error
// from a key callback aborts the handshake.
func (a Auth) loadFiles() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	var first error
	for i, f := range append(append([]string(nil), a.Identities...), a.Defaults...) {
		s, err := a.loadKey(f)
		if errors.Is(err, fs.ErrNotExist) && i >= len(a.Identities) {
			continue
		}
		if err != nil {
			a.logf("identity %s: skipped: %v", f, err)
			if first == nil {
				first = err
			}
			continue
		}
		a.logf("identity %s: %s %s", f, s.PublicKey().Type(), ssh.FingerprintSHA256(s.PublicKey()))
		signers = append(signers, s)
	}
	if len(signers) == 0 && first != nil {
		return nil, first
	}
	return signers, nil
}

// loadKey reads a private key, asking for its passphrase if it has one.
func (a Auth) loadKey(path string) (ssh.Signer, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := ssh.ParsePrivateKey(pem)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) && a.Prompt != nil {
		pass, perr := a.Prompt(fmt.Sprintf("Enter passphrase for key '%s': ", path), false)
		if perr != nil {
			return nil, perr
		}
		s, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(pass))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}
