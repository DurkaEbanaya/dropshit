Dropshit 0.1.3 (x86_64): regional subnet coverage and Vivox exclusion.

- Replace Amsterdam's exact `66.40.191.240/32` supplement with its currently announced Blizzard `66.40.191.0/24` route.
- Add Amsterdam `5.42.168.0/21` from MINA's regional list. Regional inference and source limitations are [documented](https://github.com/DurkaEbanaya/dropshit/blob/main/docs/address-supplements.md).
- Remove misclassified `85.236.97.71/32` from US east. Official Vivox ranges `85.236.96.0/21` and `85.236.104.0/23` are excluded in the data loader and privileged helper, even inside larger CIDRs.
- Authenticated startup status and boot restore clean old saved voice blocks. Reopen Dropshit after upgrading and authorize its initial check; press `a` to apply expanded regional coverage when prompted.

Packages: `dropshit_0.1.3-1_amd64.deb` for Debian 12+/Ubuntu 24.04+, `dropshit-0.1.3-1.fc.x86_64.rpm` for Fedora, `dropshit-0.1.3-1.x86_64.rpm` for openSUSE, `dropshit-0.1.3-1-x86_64.pkg.tar.zst` for Arch. RPMs are unsigned; openSUSE installation: `sudo zypper --no-gpg-checks install ./dropshit-0.1.3-1.x86_64.rpm`.

Binaries built on Debian 12 (glibc 2.36). Corresponding sources, source RPMs and `SHA256SUMS` are attached. Run `dropshit` as your normal desktop user.
