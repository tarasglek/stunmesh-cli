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
public node config, a static hosts table and an ssh_config. Only the
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
sm status -w 30s remote-01   # hosts table, live peer state
```

`make build NODE=...` builds the generic `build/sm-<os>-<arch>` and
attaches `CONFIG/NODE/node.json`, and the `ssh_config` gen.py renders
beside it, to a copy, so the repo carries no site config and one build
serves every node of an architecture. They are stored zip entries at
the end of the file: `sm config` and `sm config ssh` print them, as does
`unzip -p`. `sm config attach BINARY NODE.json OUT` attaches them to any
sm binary. `sm --config FILE <applet>` or `$STUNMESH_CLI_CONFIG=FILE`
reads them from the file system instead. Names resolve from the hosts
table only, never DNS. The device key stays in
`~/.config/stunmesh-cli/key`. build/bin/ has a symlink per applet, so
with it first in PATH plain `mosh` is the applet.

Termux on Android gets a `GOOS=android` build: Go then keeps clear of
the system calls Android's seccomp kills apps for.

## ssh and mosh

OpenSSH reaches the mesh through `ProxyCommand sm nc %h %p`, which the
attached ssh_config sets for every mesh host, so everything ssh does
(agent, known_hosts, `-L`/`-R`/`-D`, scp, rsync, git, `ControlMaster`)
works as on any network.

`sm mosh` starts mosh-server with that same ssh, as mosh does, so its
user, port and keys come from ssh_config too, then runs mosh-client
against a UDP relay on 127.0.0.1 whose other end is in the node. The
session is mosh's own: local echo prediction, the "last contact" notice,
Ctrl-^ . to quit. `sm mosh --client=PATH` picks the mosh-client. mosh
needs ssh and mosh-client here and mosh-server on the host. A binary
given its config with `--config FILE` passes it on to ssh's `sm nc` as
`STUNMESH_CLI_CONFIG`.

## One node per user

The first applet that needs the mesh starts `sm daemon` in the
background, and every later one, in any terminal, uses it, already
joined. The applets reach it over HTTP on a unix socket,
`$XDG_RUNTIME_DIR/sm.sock` or next to the key, which only the same user
may use; its log is `sm.log` beside it. With no clients and no UDP relay
a program still uses, it exits after 5 minutes; `sm down` stops it at
once, and `sm daemon [-idle 0]` runs it in the foreground. The daemon
joins every peer of the config, so on a large mesh its first dial waits
on discovery for all of them. `STUNMESH_CLI_DAEMON=off` runs a node,
narrowed to the peers the applet needs, inside the applet instead;
`STUNMESH_CLI_LOG=info` then shows its log on stderr.

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
