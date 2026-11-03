module github.com/tarasglek/stunmesh-cli

go 1.26.5

// Until the extension points are merged upstream, build against the forks
// checked out next to this repo: stunmesh-go branch userspace-tun,
// stunmesh-avahi branch main, sshd-lite branch mosh-connect.
replace (
	github.com/jpillora/sshd-lite => ../sshd-lite
	github.com/tarasglek/stunmesh-avahi => ../stunmesh-avahi
	github.com/tjjh89017/stunmesh-go => ../stunmesh-go
)

require (
	github.com/jpillora/sshd-lite v0.0.0-00010101000000-000000000000
	github.com/tarasglek/stunmesh-avahi v0.0.0-00010101000000-000000000000
	github.com/tjjh89017/stunmesh-go v1.16.0
	golang.org/x/crypto v0.58.0
	golang.org/x/term v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
)

require (
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/jpillora/jplog v1.0.2 // indirect
	github.com/jpillora/sftp v1.13.15 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.1 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
)

require (
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20260303162955-0b88c25f3fff // indirect
	github.com/charmbracelet/x/ansi v0.11.9 // indirect
	github.com/charmbracelet/x/exp/ordered v0.1.0 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/vt v0.1.0 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/wire v0.7.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mattn/go-runewidth v0.0.31 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.8.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/unixshells/mosh-go v0.5.2 // indirect
	github.com/unixshells/vt-go v0.2.0 // indirect
	github.com/xo/terminfo v1.2.0 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/mobile v0.0.0-20260709172247-6129f5bee9d5 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10 // indirect
	mvdan.cc/sh/v3 v3.14.1 // indirect
)
