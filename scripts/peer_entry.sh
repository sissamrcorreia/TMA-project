#!/bin/bash
set -e

# Configuración de rutas internas del contenedor
APP_DIR="/app/src"
CAPTURE_BIN="$APP_DIR/capture/flow_capture_json"
AGG_SCRIPT="$APP_DIR/aggregation/file_aggregation_engine.py"
TG_SCRIPT="/app/scripts/traffic_generator.py"

echo "=== [Entrypoint] Arrancando Peer: $HOSTNAME ==="

# 1. Iniciar CAPTURA (C)
echo "-> [1/3] Iniciando Agente de Captura..."
if [ -x "$CAPTURE_BIN" ]; then
    "$CAPTURE_BIN" "${INTERFACE:-eth0}" > /dev/null 2>&1 &
    PID_CAPTURE=$!
    echo "   PID Capture: $PID_CAPTURE"
else
    echo "ERROR: No encuentro el binario en $CAPTURE_BIN"
    exit 1
fi

# 2. Iniciar AGREGACIÓN (Python)
echo "-> [2/3] Iniciando Motor de Agregación..."
python3 "$AGG_SCRIPT" \
    --input-file "$APP_DIR/output/flows/current_flows.json" \
    --output-dir "$APP_DIR/output/aggregated_flows" \
    --poll-interval 5 \
    --stats-interval 30 \
    --no-privacy &
PID_AGG=$!
echo "   PID Aggregation: $PID_AGG"

# 3. Iniciar GENERADOR DE TRÁFICO
echo "-> [3/3] Iniciando Generador de Tráfico..."
PY_EXEC="python3"
if [ -f "/venv/bin/python" ]; then PY_EXEC="/venv/bin/python"; fi

$PY_EXEC "$TG_SCRIPT" \
    --interval "${TRAFFIC_INTERVAL:-5}" \
    --per-second-rate "${TRAFFIC_RATE:-2}" \
    --seed "${TRAFFIC_SEED:-1}" &
PID_TG=$!
echo "   PID Traffic Gen: $PID_TG"

_term() {
  echo "!!! Deteniendo contenedor..."
  kill -TERM "$PID_TG" "$PID_CAPTURE" "$PID_AGG" 2>/dev/null
  wait
  exit 0
}
trap _term SIGTERM SIGINT

echo "=== Sistema TMA corriendo. Logs en /app/src/output ==="
wait -n $PID_CAPTURE $PID_AGG $PID_TG