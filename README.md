# 🌐 Real-Time Network Traffic Analyzer

A live network traffic dashboard built with Scapy and Streamlit. Captures packets in real time, resolves IPs/ports to readable names, visualizes protocol and traffic breakdowns, and flags source IPs that show port-scanning behavior.

## Features

- **Live packet capture** using Scapy, with a configurable packet limit per session
- **Protocol, IP, and port breakdown** — extracts protocol, source/destination IP, ports, and packet size from every captured packet
- **Human-readable resolution** — converts raw IPs and ports into hostnames and service names (e.g. `443` → `https`), with results cached so repeated lookups are instant
- **Port-scan detection** — flags any source IP that contacts an unusually high number of distinct destination ports, with an adjustable sensitivity threshold
- **Interactive dashboard** — protocol distribution pie chart, top source/destination IPs and ports, and a sortable raw packet table, all built with Plotly and Streamlit
- **Save/reload captures** — persist a capture session to disk and reload it later without needing to re-sniff traffic

## Project Structure

```
.
├── app.py           # Streamlit UI — sidebar controls, charts, tables
├── analyzer.py       # TrafficAnalyzer — packet capture logic
├── utils.py          # Caching, IP/port resolution, port-scan detection, save/load
└── requirements.txt
```

Capture logic, business logic, and presentation are kept separate — `analyzer.py` and `utils.py` have no Streamlit dependency, so the same logic could sit behind a different UI (e.g. Flask or FastAPI) without changes.

## Setup

**Requirements:** Python 3.9+

### Using pip

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Using uv

```bash
uv venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
uv pip install -r requirements.txt
```

### Platform notes for packet capture

Scapy needs raw socket access to sniff packets:

- **Linux/macOS:** run the app with elevated permissions
- **Windows:** install [Npcap](https://npcap.com/) first

## Running

```bash
sudo streamlit run app.py   # Linux/macOS
streamlit run app.py        # Windows, after Npcap is installed
```

Open the URL Streamlit prints (usually `http://localhost:8501`), set your packet limit and port-scan threshold in the sidebar, and click **Start Capture**.

## How Port-Scan Detection Works

For each captured source IP, the app counts the number of *distinct* destination ports it contacted. A typical client talks to a handful of ports (e.g. one for DNS, one for HTTPS); a port scanner touches many in a short window. Any source IP crossing the configurable threshold (default: 15 unique ports) is surfaced in a dedicated alert table at the top of the dashboard.

## Notes

- Packet resolution (`resolve_ip`, `get_port_service`) is cached in-memory per run using `functools.lru_cache`, so the same IP or port is never looked up twice in a session.
- Saved captures are stored via `joblib` and can be reloaded from the sidebar without re-running a live capture.
