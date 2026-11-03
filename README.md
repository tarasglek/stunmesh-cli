# stunmesh-cli

One static binary that joins a [stunmesh-go](https://github.com/tjjh89017/stunmesh-go)
WireGuard mesh in userspace, without a VPN, a tun device or root, and opens
SSH and Mosh sessions to the mesh's hosts. Meant for phones and other
machines where a system VPN is unavailable or already taken.

WireGuard runs on wireguard-go's netstack inside the process; peer discovery
is the standard stunmesh-go machinery with the lease plugin from
[stunmesh-avahi](https://github.com/tarasglek/stunmesh-avahi).

Planned, not built yet: the node's public config and a static hosts table
compiled in from `cmd/stunmesh-cli/config/node.json`, which `make build
NODE=...` copies there and git ignores, so the repo carries no site
config; the private key generated on the device, never in the binary.

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
