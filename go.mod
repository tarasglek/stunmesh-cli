module github.com/tarasglek/stunmesh-cli

go 1.26.0

// Until the extension points are merged upstream, build against the forks
// checked out next to this repo: stunmesh-go branch userspace-tun,
// stunmesh-avahi branch main, sshd-lite branch mosh-connect.
replace (
	github.com/jpillora/sshd-lite => ../sshd-lite
	github.com/tarasglek/stunmesh-avahi => ../stunmesh-avahi
	github.com/tjjh89017/stunmesh-go => ../stunmesh-go
)
