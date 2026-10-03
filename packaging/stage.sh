#!/bin/sh
set -eu
root=$(dirname "$(dirname "$(realpath "$0")")")
stage=$1
binary=${2:-"$root/target/release/dropshit"}
helper=${3:-"$root/target/release/dropshit-helper"}
install -Dm755 "$binary" "$stage/usr/bin/dropshit"
install -Dm755 "$helper" "$stage/usr/libexec/dropshit-helper"
install -Dm755 "$root/packaging/clear-installed-rules.sh" "$stage/usr/share/dropshit/clear-installed-rules.sh"
install -Dm644 "$root/packaging/io.github.durkaebanaya.dropshit.policy" "$stage/usr/share/polkit-1/actions/io.github.durkaebanaya.dropshit.policy"
install -Dm644 "$root/packaging/dropshit-restore.service" "$stage/usr/lib/systemd/system/dropshit-restore.service"
install -Dm644 "$root/packaging/firewall.json" "$stage/etc/dropshit/firewall.json"
install -Dm644 "$root/LICENSE" "$stage/usr/share/licenses/dropshit/LICENSE"
install -Dm644 "$root/README.md" "$stage/usr/share/doc/dropshit/README.md"
install -d -m755 "$stage/var/lib/dropshit"
