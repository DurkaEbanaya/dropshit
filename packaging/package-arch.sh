#!/bin/bash
set -euo pipefail
root=$(dirname "$(dirname "$(realpath "$0")")")
version=$(python3 -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["package"]["version"])' "$root/Cargo.toml")
archive="$root/dist/dropshit-linux-$version.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$archive" "$root/packaging/PKGBUILD" "$root/packaging/dropshit.install" "$tmp/"
python3 - "$tmp/PKGBUILD" "$archive" <<'PY'
import hashlib, pathlib, sys
file = pathlib.Path(sys.argv[1]); digest = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
file.write_text(file.read_text().replace("sha256sums=('SKIP')", f"sha256sums=('{digest}')"))
PY
if command -v makepkg >/dev/null; then
    [[ $EUID -ne 0 ]] || { printf 'makepkg must run as a regular user\n' >&2; exit 1; }
    (cd "$tmp" && PKGDEST="$tmp" makepkg --nodeps --noconfirm --clean --force)
else
    printf 'Run this script inside Arch Linux with makepkg installed\n' >&2
    exit 1
fi
cp "$tmp/dropshit-$version-1-x86_64.pkg.tar.zst" "$root/dist/"
