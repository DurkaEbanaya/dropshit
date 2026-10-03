Dropshit 0.1.5: automatic strict single-region mode and automatic application.

- Exactly one game region left allowed: permit its networks and Vivox, reject all other destinations for the user's UDP ports 12000–64000, including unlisted relays.
- Two or more game regions left allowed: use the existing regional blocklist.
- Space toggles and automatically applies changes. No separate apply confirmation; a single authenticated helper session handles serial updates. `a` remains a retry shortcut after errors.
- Mode, single-region code and network data persist; boot restore, backend migration and clearing support both modes. Old blocklists load compatibly and migrate automatically when only one region remains.
- Packet tests exercise IPv4/IPv6, Vivox, unknown endpoints, TCP and UDP boundaries, strict/blocklist/clear transitions on nftables and iptables.

Packages for Debian 12+/Ubuntu 24.04+, Fedora, openSUSE and Arch (x86_64), corresponding sources and SHA256SUMS are attached. openSUSE: `sudo zypper --no-gpg-checks install ./dropshit-0.1.5-1.x86_64.rpm`. Run `dropshit` as your regular desktop user.
