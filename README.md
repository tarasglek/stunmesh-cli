# stunmesh-cli

One static binary, `sm`, that joins a [stunmesh-go](https://github.com/tjjh89017/stunmesh-go)
WireGuard mesh in userspace, without a VPN, a tun device or root, and
carries the system's OpenSSH and Mosh to the mesh's hosts.

```sh
make check    # tidy, vet, test, build build/sm-<arch>
```

## License

LGPL-3.0-or-later, as stunmesh-avahi.
