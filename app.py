"""
Streamlit dashboard. All display/UI logic lives here; capture logic is in
analyzer.py and everything else (caching, save/load, scan detection) is
in utils.py. Run with: streamlit run app.py
"""

import os
import streamlit as st
from scapy.all import sniff
import pandas as pd
import plotly.express as px

from analyzer import TrafficAnalyzer
from utils import save_packets, load_packets, get_port_service, resolve_ip, detect_port_scanners


def main():
    st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")
    st.title("🌐 Real-Time Network Traffic Analyzer")

    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = None

    with st.sidebar:
        st.header("Settings")
        max_packets = st.number_input("Packets to capture", 10, 1000, 100)
        start_capture = st.button("🚀 Start Capture")
        save_file = st.text_input("Filename to save/load", value="packets.joblib")
        port_scan_threshold = st.slider("Port-scan alert threshold (unique ports)", 5, 100, 15)
        if st.button("💾 Save Captured Packets"):
            if st.session_state.analyzer and st.session_state.analyzer.packets:
                save_packets(st.session_state.analyzer.packets, save_file)
                st.success(f"Packets saved to {save_file}")
            else:
                st.warning("No packets to save.")
        if st.button("📂 Load Packets from File"):
            if os.path.exists(save_file):
                loaded_packets = load_packets(save_file)
                analyzer = TrafficAnalyzer(max_packets=len(loaded_packets))
                analyzer.packets = loaded_packets
                analyzer.counter = len(loaded_packets)
                st.session_state.analyzer = analyzer
                st.success(f"Loaded {len(loaded_packets)} packets from {save_file}")
            else:
                st.error(f"File {save_file} not found.")

    if start_capture:
        st.session_state.analyzer = TrafficAnalyzer(max_packets)
        with st.spinner(f"Capturing {max_packets} packets..."):
            sniff(prn=st.session_state.analyzer.packet_handler,
                  filter="ip",
                  store=0,
                  stop_filter=st.session_state.analyzer.stop_filter)
        st.success("Capture complete!")

    if st.session_state.analyzer and st.session_state.analyzer.packets:
        analyzer = st.session_state.analyzer
        df = pd.DataFrame(analyzer.packets)

        protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        df['protocol_name'] = df['protocol'].map(protocol_map).fillna('Other')

        st.header(f"📊 Traffic Summary ({len(df)} packets analyzed)")

        flagged = detect_port_scanners(df, port_threshold=port_scan_threshold)
        if not flagged.empty:
            st.subheader("🚨 Possible Port-Scanning Activity Detected")
            flagged_display = flagged.copy()
            flagged_display['hostname'] = flagged_display['src_ip'].apply(resolve_ip)
            st.dataframe(
                flagged_display.rename(columns={
                    'src_ip': 'Source IP',
                    'unique_ports_contacted': 'Unique Ports Contacted',
                    'hostname': 'Hostname'
                }),
                hide_index=True,
                use_container_width=True
            )
        else:
            st.info(f"No source IP contacted {port_scan_threshold}+ unique ports in this capture.")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Average Packet Size", f"{df['size'].mean():.1f} bytes")
        with col2:
            st.metric("Unique Source IPs", df['src_ip'].nunique())
        with col3:
            st.metric("Unique Ports", pd.concat([df['src_port'], df['dst_port']]).nunique())

        st.subheader("Protocol Distribution")
        protocol_counts = df['protocol_name'].value_counts()
        fig = px.pie(protocol_counts, names=protocol_counts.index, values=protocol_counts.values)
        st.plotly_chart(fig, use_container_width=True)

        col4, col5 = st.columns(2)

        with col4:
            st.subheader("🔝 Top Source IPs")
            top_src_ips = df['src_ip'].value_counts().head(10)
            src_ip_df = pd.DataFrame({'ip': top_src_ips.index, 'count': top_src_ips.values})
            src_ip_df['hostname'] = src_ip_df['ip'].apply(resolve_ip)
            src_ip_df['label'] = src_ip_df.apply(
                lambda x: f"{x['ip']} ({x['hostname']})" if x['hostname'] != x['ip'] else x['ip'], axis=1)
            fig = px.bar(src_ip_df, x='label', y='count',
                         labels={'count': 'Count', 'label': 'Source IP (Hostname)'},
                         hover_data={'hostname': True, 'ip': True, 'label': False})
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(src_ip_df.rename(columns={'ip': 'IP Address', 'hostname': 'Hostname', 'count': 'Count'}),
                         hide_index=True, use_container_width=True)

        with col5:
            st.subheader("🎯 Top Destination IPs")
            top_dst_ips = df['dst_ip'].value_counts().head(10)
            dst_ip_df = pd.DataFrame({'ip': top_dst_ips.index, 'count': top_dst_ips.values})
            dst_ip_df['hostname'] = dst_ip_df['ip'].apply(resolve_ip)
            dst_ip_df['label'] = dst_ip_df.apply(
                lambda x: f"{x['ip']} ({x['hostname']})" if x['hostname'] != x['ip'] else x['ip'], axis=1)
            fig = px.bar(dst_ip_df, x='label', y='count',
                         labels={'count': 'Count', 'label': 'Destination IP (Hostname)'},
                         hover_data={'hostname': True, 'ip': True, 'label': False})
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(dst_ip_df.rename(columns={'ip': 'IP Address', 'hostname': 'Hostname', 'count': 'Count'}),
                         hide_index=True, use_container_width=True)

        with col4:
            st.subheader("🔝 Top Source Ports")
            top_src_ports = df['src_port'].value_counts().head(10)
            src_port_df = pd.DataFrame({'port': top_src_ports.index, 'count': top_src_ports.values})
            src_port_df['service'] = src_port_df['port'].apply(get_port_service)
            src_port_df['label'] = src_port_df.apply(lambda x: f"{x['port']} ({x['service']})", axis=1)
            fig = px.bar(src_port_df, x='label', y='count',
                         labels={'count': 'Count', 'label': 'Source Port (Service)'},
                         hover_data={'service': True, 'port': True, 'label': False})
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(src_port_df.rename(columns={'port': 'Port', 'service': 'Service Name', 'count': 'Count'}),
                         hide_index=True, use_container_width=True)

        with col5:
            st.subheader("🎯 Top Destination Ports")
            top_dst_ports = df['dst_port'].value_counts().head(10)
            dst_port_df = pd.DataFrame({'port': top_dst_ports.index, 'count': top_dst_ports.values})
            dst_port_df['service'] = dst_port_df['port'].apply(get_port_service)
            dst_port_df['label'] = dst_port_df.apply(lambda x: f"{x['port']} ({x['service']})", axis=1)
            fig = px.bar(dst_port_df, x='label', y='count',
                         labels={'count': 'Count', 'label': 'Destination Port (Service)'},
                         hover_data={'service': True, 'port': True, 'label': False})
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(dst_port_df.rename(columns={'port': 'Port', 'service': 'Service Name', 'count': 'Count'}),
                         hide_index=True, use_container_width=True)

        st.subheader("📄 Raw Packet Data")
        st.dataframe(df.sort_values('timestamp', ascending=False),
                     height=300,
                     column_config={
                         'timestamp': 'Timestamp',
                         'protocol_name': 'Protocol',
                         'src_ip': 'Source IP',
                         'dst_ip': 'Destination IP',
                         'src_port': 'Source Port',
                         'dst_port': 'Destination Port',
                         'size': 'Size'
                     })


if __name__ == "__main__":
    main()
