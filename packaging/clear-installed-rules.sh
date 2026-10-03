#!/bin/sh
for state in /var/lib/dropshit/*.json; do
    [ -e "$state" ] || continue
    uid=${state##*/}; uid=${uid%.json}
    case "$uid" in *[!0-9]*|'') continue ;; esac
    /usr/libexec/dropshit-helper --clear-user="$uid" || :
done
systemctl disable --now dropshit-restore.service >/dev/null 2>&1 || :
