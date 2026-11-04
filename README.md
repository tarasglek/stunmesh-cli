# stunmesh-cli

One static binary, `sm`, that joins a [stunmesh-go](https://github.com/tjjh89017/stunmesh-go)
WireGuard mesh in userspace, without a VPN, a tun device or root, and opens
SSH and Mosh sessions to the mesh's hosts. Meant for phones and other
machines where a system VPN is unavailable or already taken.

WireGuard runs on wireguard-go's netstack inside the process; peer discovery
is the standard stunmesh-go machinery with the lease plugin from
[stunmesh-avahi](https://github.com/tarasglek/stunmesh-avahi).

Everything a node needs travels in its binary, attached as a zip: the
public node config and a static hosts table. Only the private key is on
the device, made there and never in the config or binary.

## Use

```sh
sm keygen                             # once per device; prints the pubkey for mesh.yaml
# in mesh.yaml: <name>-cli: { ip: ..., port: ..., pubkey: ..., client: true }; gen.py; reinstall peers
make build NODE=<name>-cli CONFIG=<dir of mesh.yaml>   # build/sm-<name>-cli-<arch>, build/bin/sm
sm config attach build/sm-arm64 phone-cli/node.json sm-phone   # or attach one to any sm binary
export PATH=$PWD/build/bin:$PATH
sm status -w 30s remote-01            # hosts table, live peer state
sm ssh remote-01 -- uname -a          # SSH over the node, no system ssh needed
sm mosh remote-02                   # mosh-client over the node; Ctrl-^ . quits (mosh-server on the host)
sm ssh -N -L 8080:127.0.0.1:80 -R 2222:127.0.0.1:22 remote-01   # forwards both ways
sm listen 22:127.0.0.1:22             # every mesh peer reaches this device's sshd at its mesh address;
                                      # the target can be any host this device reaches
ssh -o ProxyCommand='sm nc %h %p' remote-01   # the system's OpenSSH over the node
```

build/bin/ also has a symlink per applet (ssh, mosh, nc, listen, status,
keygen), so with it first in PATH plain `ssh` and `mosh` are the applets.
The device key stays in `~/.config/stunmesh-cli/key`.

`make build NODE=...` builds the generic `build/sm-<arch>` and attaches
`CONFIG/NODE/node.json` to a copy, so the repo carries no site config and
one build serves every node of an architecture. The config is a stored
zip entry at the end of the file: `sm config` or `unzip -p sm node.json`
prints it. `sm --config FILE <applet>` or `$STUNMESH_CLI_CONFIG=FILE`
reads one from the file system instead. Names resolve from that table
only, never DNS.
`STUNMESH_CLI_LOG=info` shows the node's log on stderr.

mosh needs mosh-client here and mosh-server on the host, as mosh does.
sm starts mosh-server over SSH through the node, then runs mosh-client
against a UDP relay on 127.0.0.1 whose other end is in the node, so the
session is mosh's own: local echo prediction (`MOSH_PREDICTION_DISPLAY`),
the "last contact" notice, Ctrl-^ . to quit. `sm mosh --client=PATH`
picks the mosh-client to run. As with mosh, mosh-server runs without a
network timeout, so a phone can sleep through a long outage.

## Build

The extension points it needs are not merged upstream yet, so `go.mod`
replaces two modules with checkouts next to this one:

| Module | Checkout | Branch |
|---|---|---|
| stunmesh-go | `../stunmesh-go` | `userspace-tun` |
| stunmesh-avahi | `../stunmesh-avahi` | `main` |

```sh
make check    # vet, test, build build/sm-<arch>
```

Plain `go` commands need `-tags mobile`, which selects stunmesh-go's
embeddable node; the Makefile passes it.

## License

LGPL-3.0-or-later, as stunmesh-avahi.
