#!/usr/bin/env bash
set -euo pipefail

# Ruta app
APP_DIR="/app/src"
TG="/app/scripts/traffic_generator.py"

# Variables configurables (puedes pasarlas por environment)
INTERFACE="${INTERFACE:-}"
TRAFFIC_INTERVAL="${TRAFFIC_INTERVAL:-5}"
TRAFFIC_JITTER="${TRAFFIC_JITTER:-1.0}"
TRAFFIC_RATE="${TRAFFIC_RATE:-2.0}"
TRAFFIC_SEED="${TRAFFIC_SEED:-0}"
TRAFFIC_POOL="${TRAFFIC_POOL:-}"   # coma-sep list

cd "$APP_DIR"

# Start capture & aggregation (tu script). Se asume que requiere sudo/root.
if [ -n "$INTERFACE" ]; then
  /bin/bash ./run_system.sh "$INTERFACE" > /proc/1/fd/1 2>/proc/1/fd/2 & 
else
  /bin/bash ./run_system.sh > /proc/1/fd/1 2>/proc/1/fd/2 &
fi
PID_CAPTURE=$!

# Start traffic generator in venv if existe /venv, else con python3 del sistema
if [ -x /venv/bin/python ] && [ -f "$TG" ]; then
  export TRAFFIC_LOG="/app/src/output/traffic.log"
  if [ -n "$TRAFFIC_POOL" ]; then
    # pass pool as a single env var; the script la parsea
    /venv/bin/python "$TG" --interval "$TRAFFIC_INTERVAL" --jitter "$TRAFFIC_JITTER" --per-second-rate "$TRAFFIC_RATE" --seed "$TRAFFIC_SEED" --pool $(echo $TRAFFIC_POOL | tr ',' ' ') &
  else
    /venv/bin/python "$TG" --interval "$TRAFFIC_INTERVAL" --jitter "$TRAFFIC_JITTER" --per-second-rate "$TRAFFIC_RATE" --seed "$TRAFFIC_SEED" &
  fi
else
  echo "Warning: /venv/bin/python o $TG faltan, no se lanza traffic generator"
fi
PID_TG=$!

# Manejo de señales: forward SIGTERM/SIGINT y esperar a procesos
_term() {
  echo "Terminating..."
  kill -TERM "$PID_TG" 2>/dev/null || true
  kill -TERM "$PID_CAPTURE" 2>/dev/null || true
  wait
  exit 0
}
trap _term SIGTERM SIGINT

# Espera infinita manteniendo el proceso PID 1 vivo
wait

