#!/bin/bash
set -euo pipefail
root=$(dirname "$(dirname "$(realpath "$0")")")
version=$(python3 -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["package"]["version"])' "$root/Cargo.toml")
mkdir -p "$root/dist"
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
stage="$temp/stage"
mkdir -p "$stage/DEBIAN"
sh "$root/packaging/stage.sh" "$stage"
cat > "$stage/DEBIAN/control" <<EOF
Package: dropshit
Version: ${version}-1
Section: games
Priority: optional
Architecture: amd64
Maintainer: Dropshit <https://github.com/DurkaEbanaya/dropshit>
Depends: libc6 (>= 2.36), curl, iproute2, polkitd | policykit-1, nftables (>= 1.0.9) | iptables
Description: Rust terminal game region selector
 HTTPS regional estimates and per-user Overwatch UDP firewall rules.
EOF
printf '/etc/dropshit/firewall.json\n' > "$stage/DEBIAN/conffiles"
for script in postinst prerm postrm; do install -m755 "$root/packaging/deb-$script" "$stage/DEBIAN/$script"; done
dpkg-deb --build --root-owner-group "$stage" "$root/dist/dropshit_${version}-1_amd64.deb"
