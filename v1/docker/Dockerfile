FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# 1. Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    gcc make libpcap-dev \
    iproute2 net-tools iputils-ping curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Configurar entorno Python
COPY python-version/src/requirements.txt ./requirements.txt
RUN python3 -m venv /venv && \
    /venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /venv/bin/pip install requests

# 3. Copiar código fuente y scripts
COPY python-version/src /app/src
COPY scripts /app/scripts

# 4. Compilar el Agente C
WORKDIR /app/src/capture
RUN gcc -o flow_capture_json flow_capture_json.c -lpcap

# 5. Preparar directorios finales
WORKDIR /app/src
RUN mkdir -p output/flows output/aggregated_flows && \
    chmod +x /app/scripts/peer_entry.sh /app/scripts/traffic_generator.py

# 6. Entrypoint
ENTRYPOINT ["/app/scripts/peer_entry.sh"]

