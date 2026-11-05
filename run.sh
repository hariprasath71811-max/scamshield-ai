#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if ! command -v javac >/dev/null 2>&1; then
  echo "[ScamShield] Java 11+ is required. Install a JDK and try again." >&2
  exit 1
fi

mkdir -p out
echo "[ScamShield] Compiling..."
javac --release 11 -d out src/Main.java

echo "[ScamShield] Starting on http://localhost:8080 ..."
exec java --add-modules jdk.httpserver -cp out Main "$@"
