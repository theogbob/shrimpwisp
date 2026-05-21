#!/bin/bash
# WispMark wrapper — adapts our CLI to WispMark's expected interface.
# WispMark calls: ./wrapper PORT
# We translate to: shrimpwisp --bind 0.0.0.0:PORT

PORT="${1:-6001}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export MALLOC_CONF="dirty_decay_ms:500,muzzy_decay_ms:0"
exec "$SCRIPT_DIR/target/release/shrimpwisp" --bind "0.0.0.0:${PORT}" -w 6 --buffer-size 65535
