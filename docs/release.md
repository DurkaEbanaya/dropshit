Dropshit 0.1.1 (x86_64): redesigned terminal UI. The region list now fits the terminal width and height without wrapping; HTTPS addresses and game CIDRs are shown on demand with `d`, and `n`/`b` browse the selected region's CIDRs. Redraws occur when data or input changes instead of continuously. HTTPS latency estimates, firewall backends and saved blocks remain available.

Download the package appropriate for your distribution:

- Debian 12+ / Ubuntu 24.04+: `dropshit_0.1.1-1_amd64.deb`
- Fedora: `dropshit-0.1.1-1.fc.x86_64.rpm`
- openSUSE: `dropshit-0.1.1-1.x86_64.rpm` (unsigned; install with `sudo zypper --no-gpg-checks install ./dropshit-0.1.1-1.x86_64.rpm`)
- Arch Linux: `dropshit-0.1.1-1-x86_64.pkg.tar.zst`

The binaries were built on Debian 12 (glibc 2.36). The source tarball and source RPM, plus `SHA256SUMS`, are attached. Run `dropshit` as your normal user. See [README](https://github.com/DurkaEbanaya/dropshit#readme) for controls and the distinction between HTTPS-region measurements and game UDP latency.
