Dropshit 0.1.4 (x86_64): fix false "saved firewall rules missing" warning with nftables.

nftables automatically merges adjacent CIDRs into larger prefixes or address ranges. Status checks now read structured nft JSON and compare the actual IPv4/IPv6 address coverage instead of searching for the original CIDR strings. The output hook, owner UID, destination sets, UDP port range and rejection rule are checked too. Missing/changed rules still produce a warning. Existing selections and rules are preserved; no reapplication is required just to fix the status display.

Includes 0.1.3's Amsterdam subnet supplements and official Vivox exclusions. Real isolated-kernel regression tests cover merged prefixes, arbitrary ranges, IPv6 and missing/altered rules.

Packages: DEB for Debian 12+/Ubuntu 24.04+, separate RPMs for Fedora and openSUSE, and Arch `.pkg.tar.zst`. RPMs are unsigned; openSUSE installation: `sudo zypper --no-gpg-checks install ./dropshit-0.1.4-1.x86_64.rpm`.

Binaries built on Debian 12 (glibc 2.36). Corresponding sources, source RPMs and `SHA256SUMS` are attached. Run `dropshit` as your normal desktop user; reopen after upgrading.
