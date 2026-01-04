"""
TMA Real-Time Dashboard
=======================

A Streamlit-based dashboard for visualizing real-time network traffic telemetry.
It connects to the Aggregator service via WebSocket to receive live updates on:
- Global Throughput (Mbps)
- Active Agents and their CPU usage
- Heavy Hitter flows (Top Talkers)
- Hierarchical Subnet Traffic (Trie Visualization)
"""

import streamlit as st
import pandas as pd
import requests
import os
import time
import plotly.express as px
import plotly.io as pio
import socketio
import threading
from collections import deque

# --- Configuration & Setup ---
st.set_page_config(
    page_title="TMA | Real-Time",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

pio.templates.default = "plotly_dark"

st.markdown("""
<style>
    h1, h2, h3 { font-family: 'Inter', sans-serif; font-weight: 600; }
    .title-text {
        background: linear-gradient(90deg, #00FBA6, #00C6FF);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.5rem;
        font-weight: 800;
    }
    div[data-testid="stMetric"], div[data-testid="stMetricValue"] {
        background-color: rgba(38, 39, 48, 0.6);
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 15px;
        border-radius: 10px;
        backdrop-filter: blur(10px);
        text-align: center;
    }
    label[data-testid="stMetricLabel"] { color: #aaaaaa; font-size: 0.9rem; }
    div[data-testid="stMetricValue"] {
        background: transparent; border: none; font-size: 1.8rem !important; color: #00FBA6 !important;
    }
    .live-dot {
        height: 10px; width: 10px; background-color: #00FBA6;
        border-radius: 50%; display: inline-block;
        box-shadow: 0 0 10px #00FBA6; animation: pulse 1s infinite; margin-right: 8px;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
</style>
""", unsafe_allow_html=True)

# Constants
AGGREGATOR_URL = os.getenv("AGGREGATOR_URL", "http://aggregator:8080")
CONTROLLER_URL = os.getenv("CONTROLLER_URL", "http://host-a:5006")

# --- GLOBAL STATE (Thread-Safe Wrapper) ---
# --- GLOBAL STATE (Thread-Safe Wrapper) ---
class GlobalCache:
    """
    Thread-safe storage for real-time metrics received from the WebSocket thread.
    This cache decouples the high-frequency socket updates from the Streamlit render loop.
    """
    def __init__(self):
        self.cms_data = {}      # Stores full CMS structure (Top Flows)
        self.hll_data = {}      # Stores full HLL structure (Cardinality)
        self.total_bytes = 0    # Cumulative throughput counter
        self.agent_cpu = 0.0    # Most recent Agent CPU metric
        self.agent_cpu_map = {} # Map of Agent IP -> CPU usage
        self.rate_history = deque(maxlen=60)   # Raw bytes/sec samples for moving average
        self.chart_history = deque(maxlen=60)  # Smoothed Mbps for visual charting
        self.cpu_history = deque(maxlen=60)    # Historical CPU stats for charting
        self.raw_payload = {}   # Last raw JSON for Debug tab
        self.last_update = time.time()
        self.connected = False
        self.heavy_hitters = [] # For Trie (Icicle) visualization

@st.cache_resource
def get_cache():
    return GlobalCache()

GLOBAL_CACHE = get_cache()

# --- WEBSOCKET CLIENT THREAD ---
def start_socket_listener():
    sio = socketio.Client()
    cache = get_cache()

    @sio.on('connect')
    def on_connect():
        print("✅ Connected to Aggregator WebSocket")
        cache.connected = True

    @sio.on('disconnect')
    def on_disconnect(*args):
        print("❌ Disconnected")
        cache.connected = False

    @sio.on('traffic_data')
    def on_traffic_data(data):
        """Callback for receiving new traffic events from the Aggregator."""
        cache.connected = True
        now = time.time()
        
        cache.raw_payload = data # Save raw for Debug tab
        
        delta_bytes = data.get('total_bytes_delta', 0)
        cache.total_bytes += delta_bytes
        
        # Per Agent CPU
        agent_ip = data.get('agent_ip', 'unknown')
        cpu_val = data.get('agent_cpu', 0.0)
        cache.agent_cpu = cpu_val # Keep last seen for KPI
        cache.agent_cpu_map[agent_ip] = cpu_val
        
        cache.rate_history.append((now, delta_bytes))
        cache.cpu_history.append((now, dict(cache.agent_cpu_map))) # Snapshot
        
        # New 5-Tuple Structures
        if 'cms' in data:
            new_cms = data.get('cms', {})
            # Only update if meaningful (contains values)
            if new_cms.get('heavy_hitters_bytes'):
                cache.cms_data = new_cms

        if 'hll' in data:
            new_hll = data.get('hll', {})
            # Only update if meaningful
            if new_hll.get('summary', {}).get('cardinalities', {}).get('unique_flows', 0) > 0:
                 cache.hll_data = new_hll
            
        # Trie Data (Visual Hierarchy)
        if 'heavy_hitters' in data:
            new_hh = data.get('heavy_hitters', [])
            # PREVENT BLINKING: Only update if we have actual heavy hitters.
            # This ensures we display the "Last Known" attack state instead of
            # flashing empty screens when receiving heartbeats from idle agents.
            if new_hh:
                cache.heavy_hitters = new_hh

        cache.last_update = now

    while True:
        try:
            sio.connect(AGGREGATOR_URL, wait_timeout=10)
            sio.wait()
        except Exception as e:
            print(f"Socket Reconnect Error: {e}")
            cache.connected = False
            time.sleep(5)

if 'socket_thread' not in st.session_state:
    t = threading.Thread(target=start_socket_listener, daemon=True)
    t.start()
    st.session_state.socket_thread = t

# --- HELPER FUNCTIONS ---
def get_current_rate():
    """Calculates current throughput (bytes/sec) based on a 2-second moving window."""
    cache = get_cache()
    # Tune to 2.0s window for snappier updates
    cutoff = time.time() - 2.0
    total = 0
    history = list(cache.rate_history)
    for ts, b in history:
        if ts > cutoff: total += b
    return total / 2.0

def fetch_status():
    try:
        r = requests.get(f"{CONTROLLER_URL}/status", timeout=1.0)
        if r.status_code == 200:
            return r.json().get("mode", "unknown").upper()
    except:
        pass
    return "WAITING..."

def control_traffic(action):
    try:
        requests.post(f"{CONTROLLER_URL}/{action}", timeout=1)
        if action == "start": st.toast("Packet Storm Started!", icon="🌪️")
        else: st.toast("Traffic Normalized", icon="✅")
    except:
        st.error("Controller Offline")

# --- UI RENDER LOOP (Back to while True for No-Scroll-Reset) ---

# 1. SIDEBAR (STATIC)
with st.sidebar:
    st.markdown("## Real-Time Console")
    
    # Status Placeholder
    status_mode_placeholder = st.empty()
    
    # Switch Control
    # 1. Fetch Source of Truth
    server_mode = fetch_status()
    is_attack_active = (server_mode == "ATTACK")
    
    # 2. Render Toggle
    target_mode = st.toggle("Enable Heavy Traffic", value=is_attack_active, key="toggle_heavy_traffic")
    
    # 3. Reconcile
    if target_mode != is_attack_active:
        if target_mode:
            control_traffic("start")
            st.toast("Generating Heavy Traffic...", icon="🌊")
        else:
            control_traffic("stop")
            st.toast("Traffic Normalized", icon="🛡️")
            
        # No rerun here, let the loop catch it

    st.divider()
    cache = get_cache()
    # Placeholder for connection
    status_connection_placeholder = st.empty()
    st.caption(f"Aggregator: {AGGREGATOR_URL}") # Debug connection string


# 2. HEADER (STATIC)
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.markdown("""
        <div style="display: flex; align-items: center; gap: 15px;">
            <div class="title-text" style="margin-bottom: 0;">TMA Live</div>
            <div style="display: flex; align-items: center; background: rgba(0, 251, 166, 0.1); padding: 5px 10px; border-radius: 20px;">
                <span class="live-dot"></span>
                <span style="color:#00FBA6; font-weight: bold; font-size: 0.9em;">Connected</span>
            </div>
        </div>
    """, unsafe_allow_html=True)

# 3. STATIC KPI GRID PLACEHOLDERS
k1, k2, k3, k4 = st.columns(4)
p_k1 = k1.empty()
p_k2 = k2.empty()
p_k3 = k3.empty()
p_k4 = k4.empty()

st.markdown("---")

# 4. STATIC TABS & PLACEHOLDERS
tab1, tab2, tab3, tab4 = st.tabs(["📊 Live Metrics", "🌐 Network Map", "🖥️ System Health", "🐞 Debug / Raw"])

with tab1:
    # Row 1: Area Chart
    st.subheader("Throughput History")
    with st.container():
        p_chart = st.empty()
    
    st.divider()
    
    # Row 2: Tables & Pies
    t1_c1, t1_c2 = st.columns([2, 1])
    with t1_c1:
        st.subheader("Top Flows (Count-Min Sketch)")
        with st.container():
             p_flows = st.empty()
    with t1_c2:
        st.subheader("HLL Cardinality")
        with st.container():
             p_hll = st.empty()
        
    st.divider()
    
    # Row 3: Heavy Hitters (Trie)
    st.subheader("Heavy Hitter Subnets")
    with st.container():
        p_heavy_hitters_table = st.empty()

with tab2:
    st.subheader("Network Hierarchy (Destination IPs)")
    with st.container():
        p_tree = st.empty()
    st.divider()
    st.subheader("Top Active Subnets (/24)")
    with st.container():
        p_bar = st.empty()

with tab3:
    st.subheader("Agent CPU Utilization")
    st.caption("Real-time CPU usage of the eBPF Agent container.")
    with st.container():
        p_cpu_chart = st.empty()

with tab4:
    st.subheader("Raw Aggregator Payload")
    st.caption("Live JSON feed from WebSocket (Last received packet)")
    with st.container():
        p_raw_json = st.empty()

# Initialize last_mode in session state if not present
if 'last_mode' not in st.session_state:
    st.session_state.last_mode = server_mode

# 5. DYNAMIC LOOP
while True:
    try:
        # --- PHASE 1: FAST UI UPDATES (Cache-based) ---
        cache = get_cache()
        current_rate = get_current_rate()
        current_mode = fetch_status()
        
        # Update State Tracker (No Rerun)
        if current_mode != "WAITING" and current_mode != st.session_state.last_mode:
            st.session_state.last_mode = current_mode
            # st.rerun() # DISABLED to prevent chart jitter/duplication

        # Update KPIs

        mbps = (current_rate * 8) / 1e6
        cache.chart_history.append((time.time(), mbps))
        
        if mbps > 1000:
            p_k1.metric("Live Throughput", f"{mbps/1000:.2f} Gbps", help="Sum of Egress traffic across all agents.")
        else:
            p_k1.metric("Live Throughput", f"{mbps:.1f} Mbps", help="Sum of Egress traffic across all agents.")
            
        p_k2.metric("Agent CPU", f"{cache.agent_cpu:.1f}%")
        
        # Get HLL Stats
        hll_summary = cache.hll_data.get('summary', {})
        hll_cards = hll_summary.get('cardinalities', {})
        unique_flows = hll_cards.get('unique_flows', 0)
        unique_src = hll_cards.get('unique_src_ips', 0)
        
        p_k3.metric("Unique Flows (HLL)", unique_flows)
        p_k4.metric("Sources (HLL)", unique_src)

        # Prep Stats DataFrames
        cms_list = cache.cms_data.get('heavy_hitters_bytes', [])
        df_flows = pd.DataFrame(cms_list)
        
        # 1. Throughput Chart
        if len(cache.chart_history) > 2:
            df_hist = pd.DataFrame(list(cache.chart_history), columns=['time', 'Mbps'])
            df_hist['time'] = pd.to_datetime(df_hist['time'], unit='s')
            
            # Throughput
            fig_area = px.area(df_hist, x='time', y='Mbps', template='plotly_dark')
            fig_area.update_traces(line_color='#00FBA6', fillcolor='rgba(0, 251, 166, 0.2)')
            fig_area.update_layout(height=230, margin=dict(t=0, b=0, l=0, r=0), yaxis_title="Throughput (Mbps)")
            p_chart.plotly_chart(fig_area, use_container_width=True)
            
            # CPU (Per Agent)
            # Flatten history: [(ts, {ip1: 50, ip2: 60}), ...] -> DF
            cpu_records = []
            for ts, snapshot in cache.cpu_history:
                for ip, val in snapshot.items():
                    cpu_records.append({'time': ts, 'Agent': ip, 'CPU': val})
            
            if cpu_records:
                df_cpu = pd.DataFrame(cpu_records)
                df_cpu['time'] = pd.to_datetime(df_cpu['time'], unit='s')
                
                # Adaptive Y-Axis Scaling (Headroom)
                max_val = df_cpu['CPU'].max() if not df_cpu.empty else 0
                ceilings = [5, 10, 25, 50, 100]
                y_limit = 100
                for c in ceilings:
                    if max_val * 1.2 <= c: # Ensure 20% padding fits
                        y_limit = c
                        break
                        
                fig_cpu = px.line(df_cpu, x='time', y='CPU', color='Agent', template='plotly_dark')
                fig_cpu.update_layout(
                    height=230, 
                    margin=dict(t=0, b=0, l=0, r=0), 
                    yaxis_title="CPU (%)",
                    yaxis_range=[0, y_limit]
                )
                p_cpu_chart.plotly_chart(fig_cpu, use_container_width=True)
            else:
                p_cpu_chart.info("Waiting for CPU metrics...")
        else:
            p_chart.info("Collecting history...")

        # 2. CMS Flows Table
        if not df_flows.empty:
            # Expected cols: src_ip, dst_ip, src_port, dst_port, proto, bytes
            if 'src_ip' in df_flows.columns:
                df_show = df_flows[['src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'bytes']]
                p_flows.dataframe(
                    df_show,
                    column_config={
                        "bytes": st.column_config.ProgressColumn("Bytes", format="%d"),
                        "src_port": st.column_config.NumberColumn("SPort", format="%d"),
                        "dst_port": st.column_config.NumberColumn("DPort", format="%d"),
                    },
                    hide_index=True,
                    width="stretch"
                )
        else:
            p_flows.info("Waiting for CMS data...")

        # 3. HLL Stats (Replacing Pie)
        if hll_cards:
            hll_df = pd.DataFrame([
                {"Metric": "Unique Flows", "Value": str(unique_flows)},
                {"Metric": "Unique Sources", "Value": str(unique_src)},
                {"Metric": "Unique Dest Ports", "Value": str(hll_cards.get('unique_dst_ports', 0))},
                {"Metric": "Diversity Score", "Value": f"{hll_summary.get('diversity_score', 0):.2f}"}
            ]).astype(str) # Force all columns to string to prevent PyArrow inference errors
            p_hll.dataframe(hll_df, hide_index=True, width="stretch")
        else:
            p_hll.info("Waiting for HLL data...")

        # --- PHASE 2: SLOW UI UPDATES (NOW INSTANT via Socket) ---
        trie_data = cache.heavy_hitters
        
        if cache.connected:
            status_connection_placeholder.caption(f"Conn: 🟢 WebSocket Push | CMS Verified")
        else:
            status_connection_placeholder.error("Conn: 🔴 Disconnected")

        df_trie = pd.DataFrame(trie_data) if trie_data else pd.DataFrame()

        # 4. Heavy Hitters Table (Trie View)
        if not df_trie.empty and "prefix" in df_trie.columns:
            p_heavy_hitters_table.dataframe(
                df_trie[['prefix', 'bytes']].sort_values('bytes', ascending=False).head(10),
                column_config={ "bytes": st.column_config.ProgressColumn("Usage", format="%d") },
                hide_index=True,
                width="stretch"
            )
        else:
            if trie_data:
                    p_heavy_hitters_table.warning("Data Format Issue")
            else:
                    p_heavy_hitters_table.info("Waiting for Trie Data...")

        # --- Tab 2: Map ---
        if not df_trie.empty and "prefix" in df_trie.columns and "parent" in df_trie.columns:
            # 1. ICICLE CHART
            try:
                fig_icicle = px.icicle(
                    df_trie,
                    names='prefix',
                    parents='parent',
                    values='bytes',
                    color='bytes',
                    color_continuous_scale='Mint',
                    branchvalues='total',
                )
                fig_icicle.update_layout(
                    height=600, 
                    margin=dict(t=0, b=0, l=0, r=0),
                    uirevision='constant' # Keeps zoom/pan state across updates
                )
                p_tree.plotly_chart(fig_icicle, use_container_width=True)
            except Exception as e:
                p_tree.error(f"Icicle Error: {e}")
            
            # 2. FAIL-SAFE BAR CHART
            try:
                df_trie['mask_len'] = df_trie['prefix'].apply(lambda x: int(x.split('/')[1]) if '/' in x else 0)
                df_subnets = df_trie[df_trie['mask_len'] == 24].copy()
                
                if not df_subnets.empty:
                    df_subnets = df_subnets.sort_values('bytes', ascending=False).head(15)
                    fig_bar = px.bar(
                        df_subnets, 
                        x='bytes', 
                        y='prefix', 
                        orientation='h',
                        text_auto='.2s',
                        color='bytes',
                        color_continuous_scale='Teal'
                    )
                    fig_bar.update_layout(yaxis=dict(autorange="reversed"), height=400)
                    p_bar.plotly_chart(fig_bar, use_container_width=True)
                else:
                    p_bar.info("No /24 Subnets detected yet.")
            except Exception as e:
                p_bar.error(f"Bar Chart Error: {e}")
        else:
            p_tree.info("Waiting for Network Hierarchy...")

        # --- Tab 4: Debug ---
        if cache.raw_payload:
             p_raw_json.json(cache.raw_payload)
        else:
             p_raw_json.info("Waiting for first packet...")

    except Exception as e:
        print(f"Loop Error: {e}")
    
    time.sleep(1)