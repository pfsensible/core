#!/bin/sh
# Install only in the disposable CI appliance, never on a deployed firewall.
set -eu
test -f /root/pfsensible-ci-appliance || exit 0
seed_mount=$(mktemp -d /tmp/pfsensible-seed.XXXXXX)
trap 'umount "$seed_mount" 2>/dev/null || true; rmdir "$seed_mount"' EXIT
mount -t cd9660 -o ro /dev/cd0 "$seed_mount"
test -f "$seed_mount/authorized_keys"
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cp "$seed_mount/authorized_keys" /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
