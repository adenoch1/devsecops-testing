#!/usr/bin/env bash
set -euo pipefail

echo "[+] Running unit tests..."
pytest -q
