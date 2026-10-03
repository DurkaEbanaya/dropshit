# Dropshit

Independent GPL-3.0 Rust terminal app for Linux: regional HTTPS latency estimates and Overwatch server-network selection. It uses no code or graphics from other applications. The upstream address feed and [GCPing](https://gcping.com/) endpoints are external data sources, not dependencies bundled into Dropshit.

## Install (x86_64)

Download a package from [Releases](https://github.com/DurkaEbanaya/dropshit/releases):

- Debian 12 / Ubuntu 24.04+: `sudo apt install ./dropshit_0.1.0-1_amd64.deb`
- Fedora: `sudo dnf install ./dropshit-0.1.0-1.fc.x86_64.rpm`
- openSUSE Tumbleweed: `sudo zypper --no-gpg-checks install ./dropshit-0.1.0-1.x86_64.rpm` (RPMs are unsigned)
- Arch Linux: `sudo pacman -U ./dropshit-0.1.0-1-x86_64.pkg.tar.zst`

Run `dropshit` in a terminal **as your normal user**, never with sudo. A desktop polkit authentication agent is needed for the firewall helper (`pkexec`); on a console without an agent, the firewall commands cannot authenticate. Install `nftables >= 1.0.9` or `iptables` including IPv6 tools; the nftables backend is chosen by default. To force iptables, edit `/etc/dropshit/firewall.json` as root and set `{"backend":"iptables"}`. Keep the previous backend installed until the migration is applied.

## Controls

`↑` / `↓` (or `j` / `k`) select a region; `Space` changes its desired block state; `a` applies it; `u` removes all blocks; `s` checks the saved firewall rules; `p` or `r` updates one/all HTTPS estimates; `c` switches repeated measurement (five seconds after the previous one finishes); `R` refreshes region data; `q` quits. Block selections persist on disk; periodic measurements do not. Dropshit checks its rules on startup (polkit authentication) and warns if saved rules are missing or the selection has not been applied. Check again with `s` after external firewall changes.

The regional metric is **HTTPS response time over reused TCP/TLS connections**, not Overwatch's in-game UDP ping. It fetches the current test URLs from `https://gcping.com/api/endpoints`, warms one connection and averages three subsequent HTTPS requests. HTTP error, unavailable address or non-reused connection results in an error, not a made-up game RTT. Standard curl proxy and system routing settings are respected. `ord1` uses an Iowa regional proxy; archival `icn1` has no current game network and cannot be blocked.

Game CIDRs come from `https://stowmyy.github.io/dropship/ips.json` (`servers.overwatch[].block`). Neither its ICMP probe IPs nor the HTTPS test endpoints are used as game-server firewall destinations. Rules filter **only the invoking user's UDP destinations within the selected game CIDRs and destination ports 12000–64000**. An unrelated program using these same IPs and ports under this user can also be affected. `ss` can show current Overwatch-owned UDP destinations in the region; observations are session-only and are not treated as latency measurements. Firewall rules persist when the TUI closes; they are restored at boot by `dropshit-restore.service`. On removal, the package clears its own saved rules and disables the restore service.

## Build and verify

Install Rust stable, gcc, and build tools (no graphics toolkit), plus `curl`, `iproute2`, `polkit` and either `nftables` or `iptables`. Build with `cargo build --release --locked`, then install manually by staging binaries and packaging files from `packaging/stage.sh` or build a package using `bash packaging/package-rpm.sh` / `bash packaging/package-deb.sh` / `bash packaging/package-arch.sh` on the corresponding distro. Package binaries are compiled on Debian 12 to target glibc 2.36. A complete source tarball and source RPM are included with the release.

```sh
cargo test --locked
cargo test --locked --bin dropshit regional_https_connection_is_reused -- --ignored
DROPSHIT_KERNEL_TEST=1 unshare --user --map-current-user --keep-caps --net cargo test --locked --bin dropshit-helper nft_kernel_rule_lifecycle
DROPSHIT_KERNEL_PACKET_TEST=1 unshare --user --map-current-user --keep-caps --net cargo test --locked --bin dropshit-helper nft_blocks_only_owned_udp_game_ports_in_namespace
```

The namespace tests exercise the real kernel rules without modifying the host firewall. `iptables` can be selected for the alternative backend. The root helper accepts only validated CIDRs and a fixed action via JSON on stdin; state is owned by root under `/var/lib/dropshit/`. It never flushes unrelated tables. To remove the application use your package manager (`zypper remove dropshit`, `apt remove dropshit`, `dnf remove dropshit`, or `pacman -R dropshit`).
