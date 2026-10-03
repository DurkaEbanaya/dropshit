#!/bin/bash
set -euo pipefail
root=$(dirname "$(dirname "$(realpath "$0")")")
version=$(python3 -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["package"]["version"])' "$root/Cargo.toml")
output="$root/dist"
mkdir -p "$output"
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
name="dropshit-linux-$version"
mkdir -p "$temp/$name/bin" "$temp/rpmbuild/SOURCES"
tar -C "$root" --exclude=.git --exclude=target --exclude=dist -cf - . | tar -C "$temp/$name" -xf -
install -m755 "$root/target/release/dropshit" "$temp/$name/bin/dropshit"
install -m755 "$root/target/release/dropshit-helper" "$temp/$name/bin/dropshit-helper"
tar -C "$temp" -czf "$output/$name.tar.gz" "$name"
cp "$output/$name.tar.gz" "$temp/rpmbuild/SOURCES/"
rpmbuild -ba --define "_topdir $temp/rpmbuild" "$root/packaging/dropshit.spec"
cp "$temp"/rpmbuild/RPMS/x86_64/*.rpm "$temp"/rpmbuild/SRPMS/*.rpm "$output/"
