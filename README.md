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
export PATH=$PWD/build/bin:$PATH      # applet symlinks: status, keygen, ...
status -w 30s remote-01               # hosts table, live peer state
```

`make build NODE=...` copies `CONFIG/NODE/node.json` into
`cmd/stunmesh-cli/config/`, which git ignores, so the repo carries no site
config. Names resolve from the compiled-in table only, never DNS.
`STUNMESH_CLI_LOG=info` shows the node's log on stderr.

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
