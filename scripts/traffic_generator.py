#!/usr/bin/env python3
"""
=================================================================================================================
=================================================================================================================
Traffic generator simple y configurable.
Genera pings y peticiones HTTP aleatorias a partir de un pool de destinos.
Escribirá logs en /app/src/output/traffic.log
=================================================================================================================
=================================================================================================================
TRAFFIC_INTERVAL env var o --interval: cada cuántos segundos se lanza un lote de acciones. (por defecto 5s).
TRAFFIC_JITTER: dispersa acciones dentro del intervalo (por defecto 1s).
TRAFFIC_RATE: tasa (media) de acciones por lote (por defecto 2).
TRAFFIC_POOL env var o --pool: lista separada por comas de URLs/IPs para probar.
Logs en /app/src/output/traffic.log.
=================================================================================================================
=================================================================================================================
"""

import os
import time
import random
import subprocess
import argparse
from datetime import datetime

try:
    import requests
except Exception:
    requests = None

# Pool de URLs/hosts ejemplo (puedes editar/añadir)
DEFAULT_POOL = [
    "https://example.com",
    "https://httpbin.org/get",
    "https://jsonplaceholder.typicode.com/posts/1",
    "https://www.wikipedia.org",
    "https://www.google.com",
    "https://api.github.com",
    "http://neverssl.com/",
    # "un host local o ip": para pings
    "8.8.8.8",
    "1.1.1.1"
]

LOG_PATH = os.environ.get("TRAFFIC_LOG", "/app/src/output/traffic.log")

def log(msg):
    now = datetime.utcnow().isoformat() + "Z"
    line = f"{now} {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    except Exception:
        pass

def do_ping(host, count=1, timeout=2):
    try:
        # ping -c1 -W1 host  (POSIX)
        res = subprocess.run(["ping", "-c", str(count), "-W", str(timeout), host],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        log(f"PING {host} exit={res.returncode} out_len={len(res.stdout)}")
        return res.returncode == 0
    except Exception as e:
        log(f"PING {host} error: {e}")
        return False

def do_http(url, timeout=5):
    if requests is None:
        # Fallback a curl sin decodificar a texto (mantenemos bytes)
        try:
            res = subprocess.run(
                ["curl", "-sS", "--max-time", str(timeout), url],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,              # <--- importante: no decodifiques
                timeout=timeout + 2
            )
            out_len = len(res.stdout) if res.stdout is not None else 0
            log(f"HTTP (curl) {url} exit={res.returncode} out_len={out_len}")
            return res.returncode == 0
        except Exception as e:
            log(f"HTTP (curl) {url} error: {e}")
            return False
    # requests path
    try:
        r = requests.get(url, timeout=timeout)
        log(f"HTTP {url} status={r.status_code} len={len(r.content)}")
        return True
    except Exception as e:
        log(f"HTTP {url} error: {e}")
        return False

def choose_action(target):
    # Si target parece IP -> ping, si http -> http
    if target.startswith("http://") or target.startswith("https://"):
        return "http"
    else:
        return "ping"

def main(pool, interval, jitter, per_second_rate, seed):
    random.seed(seed)
    pool = list(pool)
    log(f"Traffic-gen started pool={len(pool)} interval={interval}s jitter={jitter}s rate={per_second_rate} seed={seed}")

    try:
        while True:
            # Cada 'interval' segundos lanzamos un número de acciones en los siguientes 'interval' segundos
            n_actions = max(1, int(random.expovariate(1.0 / per_second_rate))) if per_second_rate > 0 else 1
            # dispersamos acciones en el intervalo
            for i in range(n_actions):
                target = random.choice(pool)
                action = choose_action(target)
                if action == "http":
                    # pequeño jitter para que no sean exactamente sincronizados
                    time.sleep(random.uniform(0, jitter))
                    do_http(target)
                else:
                    time.sleep(random.uniform(0, jitter))
                    do_ping(target, count=1)
            # Espera base más jitter
            sleep_time = interval + random.uniform(-jitter, jitter)
            if sleep_time < 0.1:
                sleep_time = 0.1
            time.sleep(sleep_time)
    except KeyboardInterrupt:
        log("Traffic-gen stopped by signal")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=float(os.environ.get("TRAFFIC_INTERVAL", "5")),
                    help="Intervalo base entre lotes de acciones (segundos)")
    ap.add_argument("--jitter", type=float, default=float(os.environ.get("TRAFFIC_JITTER", "1.0")),
                    help="Jitter aleatorio para dispersar las acciones (segundos)")
    ap.add_argument("--per-second-rate", type=float, default=float(os.environ.get("TRAFFIC_RATE", "2.0")),
                    help="Tasa media de acciones por lote (usar >0)")
    ap.add_argument("--seed", type=int, default=int(os.environ.get("TRAFFIC_SEED", "0")),
                    help="Seed aleatorio (0 para aleatorio)")
    ap.add_argument("--pool", nargs="*", default=None, help="Lista de destinos/URLs")
    args = ap.parse_args()

    pool = args.pool or os.environ.get("TRAFFIC_POOL")
    if isinstance(pool, str):
        pool = [p.strip() for p in pool.split(",") if p.strip()]
    if not pool:
        pool = DEFAULT_POOL

    seed = args.seed if args.seed != 0 else random.randint(1, 1000000)
    main(pool, args.interval, args.jitter, args.per_second_rate, seed)

