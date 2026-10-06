Dropshit 0.1.6: fix Discord voice/video being captured by per-user UDP filtering.

- Exclude UDP destination ports **1541, 19294–19344 and 50000–65535** on IPv4/IPv6, in both strict allowlist and regional blocklist modes. The narrower 50000–50032 range is included. TCP/443 was already unaffected.
- Effective filtered ranges: **12000–19293 and 19345–49999**. These exceptions apply to all programs; Overwatch using the exception ports will also bypass Dropshit. Rules still match the whole user, not a specific executable.
- nftables generates only the reduced port ranges; iptables adds a leading RETURN for Discord ports within its owned chain. No ACCEPT rules override the system firewall.
- Status validation detects old rules missing the exception; restart the app after upgrading to automatically replace them with the saved selection. Boot restore also uses the corrected rules. Existing running helper sessions continue using their old binary until closed.
- Isolated kernel tests cover real UDP delivery at every exception boundary, TCP/443, IPv4/IPv6, mode switches, legacy-rule migration and clearing on nftables and iptables.

Packages for Debian 12+/Ubuntu 24.04+, Fedora, openSUSE and Arch (x86_64), corresponding sources and SHA256SUMS are attached. openSUSE: `sudo zypper --no-gpg-checks install ./dropshit-0.1.6-1.x86_64.rpm`. Run `dropshit` as your regular desktop user.
