import streamlit as st
import pandas as pd
import json
import time
import os

# Page configuration
st.set_page_config(page_title="Network Traffic Monitor", layout="wide")
st.title("📊 Data Center Traffic Monitor")

# Path to the data file
DATA_PATH = "../python-version/src/output/flows/current_flows.json"

def load_data():
    if os.path.exists(DATA_PATH):
        try:
            with open(DATA_PATH, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return None
    return None

# Placeholder for real-time updates
placeholder = st.empty()

while True:
    data = load_data()
    
    with placeholder.container():
        if data and "flows" in data:
            df = pd.DataFrame(data['flows'])
            
            # ALERT PANEL (DDoS & Scanner Detection)
            # DDoS: if >3 hosts target the same Victim IP
            target_counts = df.groupby('dst_ip').src_ip.nunique()
            ddos_targets = target_counts[target_counts > 3].index.tolist()
            
            # Scanner Detection: If one source targets many different IPs
            scanner_counts = df.groupby('src_ip').dst_ip.nunique()
            scanners = scanner_counts[scanner_counts > 5].index.tolist()

            if ddos_targets or scanners:
                if ddos_targets:
                    st.error(f"🚨 **DDoS ALERT:** Targets detected: {', '.join(ddos_targets)}")
                if scanners:
                    st.warning(f"⚠️ **SCANNER DETECTED:** Sources: {', '.join(scanners)}")
            else:
                st.success("✅ **Network Status:** Healthy (No anomalies detected)")

            # KEY METRICS
            col1, col2, col3 = st.columns(3)
            col1.metric("Active Flows", data.get('flow_count', 0))
            col2.metric("Total Packets", int(df['packet_count'].sum()))
            col3.metric("Throughput (Bytes)", f"{df['byte_count'].sum():,}")

            # VISUALIZATIONS
            st.subheader("Top 5 Bandwidth Consumers (Heavy Hitters)")
            # Grouping by Source IP to find Heavy Hitters
            top_senders = df.groupby('src_ip')['byte_count'].sum().sort_values(ascending=False).head(5)
            st.bar_chart(top_senders)

            # Detailed Traffic Table
            with st.expander("View Raw Flow Data"):
                st.dataframe(df[['src_ip', 'dst_ip', 'protocol', 'packet_count', 'byte_count']])
        else:
            st.info("Waiting for incoming traffic data from the Aggregator...")

    # Polling interval (1-2 seconds)
    time.sleep(2)