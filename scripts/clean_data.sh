#!/usr/bin/env bash
set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
DATA_DIR="$ROOT/data"

echo "==> Limpiando carpetas de datos en: $DATA_DIR"

if [ -d "$DATA_DIR" ]; then
  for d in "$DATA_DIR"/peer*; do
    if [ -d "$d" ]; then
      echo " - Limpiando $d"
      rm -rf "$d"/*
    fi
  done
else
  echo " - No existe $DATA_DIR, creando..."
  mkdir -p "$DATA_DIR"
fi

echo "==> Hecho."

