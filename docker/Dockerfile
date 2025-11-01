FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Paquetes necesarios para Python, compilación de flow_capture_json y libpcap
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    gcc make libpcap-dev \
    iproute2 net-tools iputils-ping curl ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# Directorio de trabajo de la app
WORKDIR /app

# Copiamos primero requirements para cachear capas
COPY ../python-version/src/requirements.txt ./requirements.txt
RUN python3 -m venv /venv && /venv/bin/pip install -r requirements.txt

# Copiamos el resto del código fuente de la versión Python
COPY ../python-version/src ./src

# Precreamos rutas de salida (igualmente se montarán volúmenes)
RUN mkdir -p /app/src/output/flows /app/src/output/aggregated_flows

# Usuario root para capacidades de captura dentro del contenedor
USER root

# Por defecto ejecutamos el lanzador de tu sistema
# Se puede sobreescribir la interfaz con INTERFACE=eth0
WORKDIR /app/src

# Copiamos script y entrypoint
COPY scripts /app/scripts
COPY scripts/peer_entry.sh /usr/local/bin/peer_entry.sh
RUN chmod +x /usr/local/bin/peer_entry.sh /app/scripts/traffic_generator.py

ENTRYPOINT ["/usr/local/bin/peer_entry.sh"]

