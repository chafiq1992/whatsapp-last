#!/usr/bin/env bash
set -euo pipefail

# Directory containing prebuilt wheels. Defaults to ../wheelhouse relative to this script.
WHEEL_DIR="${WHEEL_DIR:-$(cd "$(dirname "$0")"/.. && pwd)/wheelhouse}"

if [ ! -d "$WHEEL_DIR" ]; then
  echo "Wheel directory '$WHEEL_DIR' not found."
  echo "Please download the required wheels as documented in README.md."
  exit 1
fi

pip install --no-index --find-links="$WHEEL_DIR" -r backend/requirements.txt
pip install --no-index --find-links="$WHEEL_DIR" -r requirements-test.txt
