#!/usr/bin/env bash
# Read-only: copies Cowrie's real config + fake files out of the container so we
# can see exactly which keys exist before changing anything. Changes nothing.
set -e
OUT="$HOME/cowrie-inspect"
mkdir -p "$OUT"

echo "=== 1. container name ==="
CID=$(sudo docker ps --filter ancestor=cowrie/cowrie --format '{{.Names}}' | head -1)
[ -z "$CID" ] && CID=$(sudo docker ps --format '{{.Names}}' | grep -i cowrie | head -1)
echo "  -> $CID"
[ -z "$CID" ] && { echo "  no cowrie container running"; exit 1; }

echo "=== 2. where cowrie lives inside it ==="
sudo docker exec "$CID" sh -c 'ls -d /cowrie/cowrie-git 2>/dev/null || ls -d /cowrie* 2>/dev/null'

echo "=== 3. copy config + honeyfs out ==="
sudo docker cp "$CID:/cowrie/cowrie-git/etc/cowrie.cfg.dist" "$OUT/" 2>/dev/null && echo "  got cowrie.cfg.dist"
sudo docker cp "$CID:/cowrie/cowrie-git/etc/cowrie.cfg"      "$OUT/" 2>/dev/null && echo "  got cowrie.cfg (active)" || echo "  no active cowrie.cfg (using defaults)"
sudo docker cp "$CID:/cowrie/cowrie-git/honeyfs"             "$OUT/" 2>/dev/null && echo "  got honeyfs/"
sudo docker cp "$CID:/cowrie/cowrie-git/share/cowrie/fs.pickle" "$OUT/" 2>/dev/null && echo "  got fs.pickle"
sudo chown -R "$USER" "$OUT"

echo "=== 4. the identity keys we care about ==="
grep -nE '^\[|hostname|kernel_version|kernel_build_string|hardware_platform|operating_system' \
     "$OUT/cowrie.cfg.dist" | grep -vE '^\s*#' | head -30

echo "=== 5. the fake files that leaked ==="
echo "--- /proc/version ---"; cat "$OUT/honeyfs/proc/version" 2>/dev/null
echo "--- /etc/os-release ---"; cat "$OUT/honeyfs/etc/os-release" 2>/dev/null || echo "  (missing — that's why it printed empty)"
echo "--- /etc/issue ---"; cat "$OUT/honeyfs/etc/issue" 2>/dev/null

echo
echo "Everything saved to $OUT — nothing was modified."
