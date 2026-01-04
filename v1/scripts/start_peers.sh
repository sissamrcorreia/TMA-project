#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
COMPOSE_FILE="$ROOT_DIR/docker/docker-compose.yml"
CLEAN_SCRIPT="$ROOT_DIR/scripts/clean_data.sh"

echo "### START_PEERS: Iniciando procedimiento..."

# 1) Pregunta/avisa y limpia datos antes de levantar (por defecto limpia)
echo "-> Limpiando carpetas data/ (llamando a $CLEAN_SCRIPT)..."
if [ -x "$CLEAN_SCRIPT" ]; then
  "$CLEAN_SCRIPT"
else
  echo "   Aviso: $CLEAN_SCRIPT no encontrado o no ejecutable. Saltando limpieza."
fi

# 2) Crear carpetas data/ si no existen
for i in 1 2 3 4 5; do
  DIR="$ROOT_DIR/data/peer$i"
  if [ ! -d "$DIR" ]; then
    echo "-> Creando directorio $DIR"
    mkdir -p "$DIR"
  fi
done

# 3) Construir la imagen (solo necesaria si hay cambios en Dockerfile)
echo "-> Construyendo imagen base (peer1)..."
docker compose -f "$COMPOSE_FILE" build --no-cache

# 4) Levantar los peers en modo detached
echo "-> Levantando los 5 peers (docker compose up -d)..."
docker compose -f "$COMPOSE_FILE" up -d

echo "-> Esperando 3s para que los contenedores inicialicen..."
sleep 3

# 5) Mostrar el estado y primeros logs breves
echo "-> Estado de containers:"
docker compose -f "$COMPOSE_FILE" ps

echo "-> Mostrando logs breves de cada peer (últimas 10 líneas):"
for i in 1 2 3 4 5; do
  echo "---- logs peer$i ----"
  docker compose -f "$COMPOSE_FILE" logs --no-color --tail=10 peer$i || true
done

echo "### START_PEERS: Terminado. Usa 'docker compose -f $COMPOSE_FILE ps' y 'docker compose -f $COMPOSE_FILE logs -f peer1' para ver más."

