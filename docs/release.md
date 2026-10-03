First independent Dropshit Linux release (x86_64). Rust terminal UI, regional HTTPS latency measurements without ICMP, visible game-server network selection, per-user nftables/iptables firewall helper, and warnings for missing saved rules.

Download the package appropriate for your distribution:

- Debian 12+ / Ubuntu 24.04+: `dropshit_0.1.0-1_amd64.deb`
- Fedora: `dropshit-0.1.0-1.fc.x86_64.rpm`
- openSUSE: `dropshit-0.1.0-1.x86_64.rpm` (unsigned; install with `sudo zypper --no-gpg-checks install ./dropshit-0.1.0-1.x86_64.rpm`)
- Arch Linux: `dropshit-0.1.0-1-x86_64.pkg.tar.zst`

The binaries were built on Debian 12 (glibc 2.36). The source tarball and source RPM, plus `SHA256SUMS`, are attached. Run `dropshit` as your normal user. See [README](https://github.com/DurkaEbanaya/dropshit#readme) for controls and the distinction between HTTPS-region measurements and game UDP latency.
