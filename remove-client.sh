#!/usr/bin/env bash
set -euo pipefail
exec python3 /etc/amnezia/amneziawg/cascade-clients.py remove "$@"
