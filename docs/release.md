Dropshit 0.1.2 (x86_64): adds exact user-observed peers missing from the external network feed: `66.40.191.240/32` to Netherlands and `85.236.97.71/32` to US east. IPinfo and ipwho.is report Amsterdam and Boston respectively. Geographic grouping does not verify a game datacenter code; the Unity-owned Boston peer may be voice traffic. Selecting its region blocks that peer's UDP ports 12000–64000 too. Existing saved selections missing new addresses now show an unapplied warning; press `a` to update rules. See [address provenance](https://github.com/DurkaEbanaya/dropshit/blob/main/docs/address-supplements.md).

Download the package appropriate for your distribution:

- Debian 12+ / Ubuntu 24.04+: `dropshit_0.1.2-1_amd64.deb`
- Fedora: `dropshit-0.1.2-1.fc.x86_64.rpm`
- openSUSE: `dropshit-0.1.2-1.x86_64.rpm` (unsigned; install with `sudo zypper --no-gpg-checks install ./dropshit-0.1.2-1.x86_64.rpm`)
- Arch Linux: `dropshit-0.1.2-1-x86_64.pkg.tar.zst`

The binaries were built on Debian 12 (glibc 2.36). The source tarball and source RPM, plus `SHA256SUMS`, are attached. Run `dropshit` as your normal user. See [README](https://github.com/DurkaEbanaya/dropshit#readme) for controls and the distinction between HTTPS-region measurements and game UDP latency.
