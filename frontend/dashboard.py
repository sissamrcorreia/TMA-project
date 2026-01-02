import streamlit as st
import pandas as pd
import json
import time
import glob
import os

# Page configuration
st.set_page_config(page_title="Network Traffic Monitor", layout="wide")

# Ruta base donde Docker monta los volúmenes
BASE_DATA_DIR = "data"
PEERS = ["peer1", "peer2", "peer3", "peer4", "peer5"]

# --- 2. FUNCIONES DE AYUDA (NUEVO: Para extraer IPs de los strings de flujo) ---
def parse_flow_key(flow_key):
    """
    Convierte '192.168.1.1:1234->10.0.0.1:80/TCP' 
    en ('192.168.1.1', '10.0.0.1')
    """
    try:
        # Formato esperado: src:port->dst:port/PROTO
        parts = flow_key.split('->')
        src_part = parts[0]
        dst_part = parts[1]
        
        src_ip = src_part.split(':')[0]
        dst_ip = dst_part.split(':')[0]
        return src_ip, dst_ip
    except:
        return None, None

def get_latest_summary(peer_name):
    """Lee el último JSON generado por el agente Python."""
    search_path = os.path.join(BASE_DATA_DIR, peer_name, "aggregated_flows", "summary_*.json")
    files = glob.glob(search_path)
    if not files:
        return None
    
    # Coger el más reciente por fecha de modificación
    latest_file = max(files, key=os.path.getctime)
    try:
        with open(latest_file, 'r') as f:
            data = json.load(f)
            data['peer'] = peer_name
            return data
    except:
        return None

def load_data(selected_view):
    """Carga y consolida datos de los peers seleccionados."""
    consolidated = {
        'total_bytes': 0, 
        'total_packets': 0, 
        'flow_count': 0,
        'scanners': [], 
        'heavy_hitters': [],
        'ddos_victims': [] # <--- NUEVO CAMPO PARA DDoS
    }
    
    peers_to_read = PEERS if selected_view == "Global (All Peers)" else [selected_view]
    
    # Diccionario temporal para detectar DDoS: {dst_ip: {set de src_ips}}
    ddos_tracker = {}

    active_peers = 0
    for peer in peers_to_read:
        data = get_latest_summary(peer)
        if data:
            active_peers += 1
            # 1. Sumar métricas
            consolidated['total_bytes'] += data.get('cms', {}).get('total_bytes', 0)
            consolidated['total_packets'] += data.get('cms', {}).get('total_packets', 0)
            consolidated['flow_count'] += data.get('hll', {}).get('cardinalities', {}).get('unique_flows', 0)
            
            # 2. Recolectar Scanners (HLL)
            scanners = data.get('hll', {}).get('port_scanners', [])
            for s in scanners:
                s['origin_peer'] = peer
                consolidated['scanners'].append(s)
                
            # 3. Procesar Heavy Hitters y buscar DDoS (LÓGICA NUEVA)
            hh = data.get('cms', {}).get('heavy_hitters_bytes', [])
            for h in hh:
                h['detected_by'] = peer
                consolidated['heavy_hitters'].append(h)
                
                # Análisis DDoS: Extraer IPs del flujo heavy hitter
                # Si una IP destino recibe tráfico pesado de muchas fuentes, es sospechoso
                s_ip, d_ip = parse_flow_key(h['flow'])
                if s_ip and d_ip:
                    if d_ip not in ddos_tracker:
                        ddos_tracker[d_ip] = set()
                    ddos_tracker[d_ip].add(s_ip)

    # 4. Determinar víctimas de DDoS
    # Regla: Si una IP destino recibe tráfico pesado de >= 3 IPs origen distintas -> DDoS Alert
    for dst_ip, attackers in ddos_tracker.items():
        if len(attackers) >= 3: 
            consolidated['ddos_victims'].append({
                'victim': dst_ip,
                'attackers_count': len(attackers),
                'attackers': list(attackers)
            })

    return consolidated, active_peers

# --- 3. BARRA LATERAL ---
st.sidebar.title("🔧 Control Panel")
view_mode = st.sidebar.selectbox("Select View Source:", ["Global (All Peers)"] + PEERS)
st.sidebar.markdown("---")
st.sidebar.caption("Refreshing every 2 seconds...")

# --- 4. INTERFAZ PRINCIPAL ---
st.title("📊 Data Center Traffic Monitor")

placeholder = st.empty()

while True:
    data, active_count = load_data(view_mode)
    
    with placeholder.container():
        # A. ESTADO DE AGENTES
        if active_count == 0:
            st.warning("⏳ Waiting for agents... (No data found yet)")
        else:
            # B. PANEL DE ALERTAS DE SEGURIDAD (Scanner + DDoS)
            scanners = data['scanners']
            ddos_victims = data['ddos_victims']
            
            # Lógica de visualización de alertas
            if not scanners and not ddos_victims:
                st.success("✅ **Network Status:** Healthy (No anomalies detected)")
            else:
                # --- NUEVA ALERTA DDoS (ROJA) ---
                if ddos_victims:
                    for d in ddos_victims:
                        st.error(f"🚨 **DDoS ATTACK DETECTED:** Victim `{d['victim']}` is being targeted by {d['attackers_count']} heavy flows!")
                        with st.expander(f"Ver detalles del ataque a {d['victim']}"):
                            st.write(f"Atacantes: {', '.join(d['attackers'])}")
                
                # --- ALERTA SCANNERS (AMARILLA) ---
                if scanners:
                    attacker_ips = list(set([s['ip'] for s in scanners]))
                    st.warning(f"⚠️ **PORT SCANNER DETECTED:** {len(attacker_ips)} IPs are scanning network ports.")

            st.divider()

            # C. MÉTRICAS CLAVE
            col1, col2, col3 = st.columns(3)
            col1.metric("Active Flows (Approx)", data['flow_count'])
            col2.metric("Total Packets", f"{data['total_packets']:,}")
            
            # Formateo Bytes (KB/MB/GB)
            bytes_val = data['total_bytes']
            if bytes_val > 1024**3:
                bytes_str = f"{bytes_val/1024**3:.2f} GB"
            elif bytes_val > 1024**2:
                bytes_str = f"{bytes_val/1024**2:.2f} MB"
            else:
                bytes_str = f"{bytes_val/1024:.2f} KB"
            col3.metric("Throughput", bytes_str)

            # D. GRÁFICA HEAVY HITTERS
            st.subheader("🏆 Top Bandwidth Consumers (Heavy Hitters)")
            
            if data['heavy_hitters']:
                df_hh = pd.DataFrame(data['heavy_hitters'])
                # Ordenar y coger Top 10
                df_top = df_hh.sort_values('bytes', ascending=False).head(10)
                
                st.bar_chart(data=df_top, x='flow', y='bytes', color='detected_by')
                
                with st.expander("View Raw Flow Data"):
                    st.dataframe(df_top[['flow', 'bytes', 'detected_by']], use_container_width=True)
            else:
                st.info("Collecting traffic statistics...")

    time.sleep(2)