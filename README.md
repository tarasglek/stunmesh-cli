# stunmesh-cli

One binary, `sm`, that joins a [stunmesh-go](https://github.com/tjjh89017/stunmesh-go)
WireGuard mesh in userspace, without a VPN, a tun device or root, and
carries the system's OpenSSH and Mosh to the mesh's hosts. Meant for
phones and other machines where a system VPN is unavailable or already
taken.

WireGuard runs on wireguard-go's netstack inside the process; peer
discovery is the standard stunmesh-go machinery with the lan and lease
plugins from [stunmesh-avahi](https://github.com/tarasglek/stunmesh-avahi).

Everything a node needs travels in its binary, attached as a zip: the
public node config and a static hosts table. Only the
private key is on the device, made there and never in the config or
binary.

## Use

```sh
sm keygen                    # once per device; prints the pubkey for mesh.yaml
# mesh.yaml: <name>-cli: { ip: ..., port: ..., pubkey: ..., client: true }; gen.py; reinstall peers
make build NODE=<name>-cli CONFIG=<dir of mesh.yaml>            # build/sm-<name>-cli-linux-<arch>
make build GOOS=android GOARCH=arm64 NODE=<name>-cli CONFIG=... # for Termux on a phone
export PATH=$PWD/build/bin:$PATH
sm config ssh > ~/.ssh/sm.conf   # then "Include sm.conf" at the top of ~/.ssh/config
ssh remote-01                # the system's OpenSSH over the node
sm mosh remote-02            # mosh over the node; Ctrl-^ . quits
sm --expose 22 config ssh > ~/.ssh/sm.conf  # also serve local sshd to the host ssh'd to
```

`make build NODE=...` builds the generic `build/sm-<os>-<arch>` and
attaches `CONFIG/NODE/node.json` to a copy, so the repo carries no site
config and one build serves every node of an architecture. It is a
stored zip entry at the end of the file: `sm config` prints it, as does
`unzip -p`. `sm config attach BINARY NODE.json OUT` attaches one to any
sm binary. `sm --config FILE <applet>` or `$STUNMESH_CLI_CONFIG=FILE`
reads it from the file system instead. Names resolve from the hosts
table only, never DNS. The device key stays in
`~/.config/stunmesh-cli/key`. build/bin/ has a symlink per applet, so
with it first in PATH plain `mosh` is the applet.

Termux on Android gets a `GOOS=android` build: Go then keeps clear of
the system calls Android's seccomp kills apps for. Other Android apps'
shells may run a file of theirs only through the linker, as
`/system/bin/linker64 PATH ARGS`; `sm config ssh` writes the
ProxyCommand so.

## ssh and mosh

OpenSSH reaches the mesh through `ProxyCommand sm nc %h %p`, which
`sm config ssh` sets for every host in the hosts table, with sm as it
was run: by its full path, config and linker, so everything ssh does
(agent, known_hosts, `-L`/`-R`/`-D`, scp, rsync, git, `ControlMaster`)
works as on any network.

`sm mosh` starts mosh-server with that same ssh, as mosh does, so its
user, port and keys come from ssh_config too, then runs mosh-client
against a UDP relay on 127.0.0.1 whose other end is in the node. The
session is mosh's own: local echo prediction, the "last contact" notice,
Ctrl-^ . to quit. `sm mosh --client=PATH` picks the mosh-client. mosh
needs ssh and mosh-client here and mosh-server on the host. ssh's
`sm nc` is the node while ssh starts mosh-server; `sm mosh` takes over
once it exits.

## One node per device, one session at a time

Every applet that needs the mesh runs the node in its own process, joined
only to the peer it talks to, and the node ends with the process: no
daemon, no socket, no state on disk. The node's fixed UDP `listen_port`
is its lock. While one process holds it, another `sm nc` or `sm mosh` on
the device, from any app or user, fails at once with "already running"
instead of fighting it for the peer. Sessions to one host can share a
process with ssh's own `ControlMaster auto` (without `ControlPersist`,
which would hold the node after the session).

`sm --expose PORT <applet>` (repeatable) also serves TCP `PORT` on
`127.0.0.1` at the node's mesh address, for as long as that process is
the node: with `sm --expose 22 config ssh`, every `ssh` through the mesh
lets the host at the other end `ssh` back to this device while the
session is up. Only that host is a peer, so only it can connect.
`STUNMESH_CLI_LOG=info` shows the node's log, with each exposed
connection, on stderr.

## Build

The node is stunmesh-go's `userspace` package, on its main branch until
a release has it.

```sh
make check    # tidy, vet, test, build build/sm-linux-<arch>
```

Tests start WireGuard nodes and bind ports; run them in a network
namespace (see `.pi/skills/netns-testing`).

## License

LGPL-3.0-or-later, as stunmesh-avahi.
