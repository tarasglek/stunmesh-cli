// SPDX-License-Identifier: LGPL-3.0-or-later

package sshc

import (
	"bufio"
	"io"
	"strings"
)

// ConfigUser is the User an ssh_config gives for host, the name as the
// user typed it, or "" if none does. It follows OpenSSH: the first value
// found wins; a Host line applies when one of its patterns, with * and ?,
// matches the host regardless of case and none of its !negated ones does;
// keywords are case-insensitive and take "key value" or "key=value". Only
// User is read: HostName, Port and the like would route around the mesh
// hosts table. Match blocks other than "Match all" are skipped, and
// Include is not followed.
func ConfigUser(r io.Reader, host string) (string, error) {
	host = strings.ToLower(host)
	applies := true // lines before the first Host apply to every host
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		key, val := configLine(sc.Text())
		switch strings.ToLower(key) {
		case "host":
			applies = hostMatches(strings.Fields(val), host)
		case "match":
			applies = strings.EqualFold(strings.TrimSpace(val), "all")
		case "user":
			if applies && val != "" {
				return val, nil
			}
		}
	}
	return "", sc.Err()
}

// configLine splits an ssh_config line into its keyword and its value,
// unquoted; comments and blank lines give "".
func configLine(line string) (key, val string) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", ""
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	key, val = line[:i], strings.TrimLeft(line[i:], " \t")
	val = strings.TrimSpace(strings.TrimPrefix(val, "="))
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return key, val
}

func hostMatches(patterns []string, host string) bool {
	matched := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		if glob(strings.ToLower(strings.TrimPrefix(p, "!")), host) {
			if neg {
				return false
			}
			matched = true
		}
	}
	return matched
}

// glob matches s against p, where * is any run and ? any one character.
func glob(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for i := len(s); i >= 0; i-- {
				if glob(p[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
		default:
			if s == "" || s[0] != p[0] {
				return false
			}
		}
		p, s = p[1:], s[1:]
	}
	return s == ""
}
