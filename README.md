# stunmesh-cli

One static binary that joins a [stunmesh-go](https://github.com/tjjh89017/stunmesh-go)
WireGuard mesh in userspace, without a VPN, a tun device or root, and opens
SSH and Mosh sessions to the mesh's hosts. Meant for phones and other
machines where a system VPN is unavailable or already taken.

WireGuard runs on wireguard-go's netstack inside the process; peer discovery
is the standard stunmesh-go machinery with the lease plugin from
[stunmesh-avahi](https://github.com/tarasglek/stunmesh-avahi).

The node's public config and a static hosts table are compiled in; the
private key is made on the device and never in the config or binary.

## Use

```sh
build/bin/keygen                      # once per device; prints the pubkey for mesh.yaml
# in mesh.yaml: <name>-cli: { ip: ..., port: ..., pubkey: ..., client: true }; gen.py; reinstall peers
make build NODE=<name>-cli CONFIG=<dir of mesh.yaml>
export PATH=$PWD/build/bin:$PATH      # applet symlinks: ssh, mosh, nc, listen, status, keygen
status -w 30s remote-01               # hosts table, live peer state
ssh -o ProxyCommand='nc %h %p' remote-01   # OpenSSH over the mesh
ssh remote-01 -- uname -a             # or the ssh applet, no system ssh needed
mosh remote-02                      # Mosh over the node; Ctrl-^ . quits (mosh-server on the host)
ssh -N -L 8080:127.0.0.1:80 -R 2222:127.0.0.1:22 remote-01   # forwards both ways
listen 22:127.0.0.1:22               # every mesh peer reaches this device's sshd at its mesh address;
                                      # the target can be any host this device reaches
```

`make build NODE=...` copies `CONFIG/NODE/node.json` into
`cmd/stunmesh-cli/config/`, which git ignores, so the repo carries no site
config. Names resolve from the compiled-in table only, never DNS.
`STUNMESH_CLI_LOG=info` shows the node's log on stderr.

mosh needs mosh-server on the host. As with mosh, mosh-server runs
without a network timeout: it stays until the session returns, quits
(Ctrl-^ . or the shell exiting) or is killed, so a phone can sleep
through a long outage. Unlike mosh, there is no local echo prediction
and no "last contact" notice: while the network is down, typing shows
nothing and appears once it is back.

## Build

The extension points it needs are not merged upstream yet, so `go.mod`
replaces three modules with checkouts next to this one:

| Module | Checkout | Branch |
|---|---|---|
| stunmesh-go | `../stunmesh-go` | `userspace-tun` |
| stunmesh-avahi | `../stunmesh-avahi` | `main` |
| sshd-lite | `../sshd-lite` | `mosh-connect` |

```sh
make check    # vet, test, build build/stunmesh-cli-<arch>
```

Plain `go` commands need `-tags mobile`, which selects stunmesh-go's
embeddable node; the Makefile passes it.

## License

LGPL-3.0-or-later, as stunmesh-avahi.
