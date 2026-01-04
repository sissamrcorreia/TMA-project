#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
COMPOSE_FILE="$ROOT_DIR/docker/docker-compose.yml"

echo "### STOP_PEERS: Deteniendo el stack..."

# 1) docker compose down (mantiene las carpetas data/ para inspección)
docker compose -f "$COMPOSE_FILE" down

# 2) (Opcional) limpiar imágenes intermedias creadas por build
echo "-> Opción: limpiar imagen local 'tma/peer:latest' (si la quieres eliminar, descomenta la línea siguiente)"
# docker image rm tma/peer:latest || true

echo "### STOP_PEERS: Hecho."

