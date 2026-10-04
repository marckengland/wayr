#!/usr/bin/env bash
# Run wayr straight from a checkout without installing it.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH="$DIR${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m wayr "$@"
