"""
Packet capture logic.

TrafficAnalyzer wraps Scapy's sniff() with a small state machine: it
collects packets up to a max count, pulling out just the fields the
dashboard needs (protocol, src/dst IP, ports, size) instead of keeping
raw packet objects.
"""

from scapy.all import IP, TCP, UDP


class TrafficAnalyzer:
    def __init__(self, max_packets=100):
        self.packets = []
        self.counter = 0
        self.max_packets = max_packets

    def packet_handler(self, packet):
        """Called by scapy.sniff() once per captured packet."""
        self.counter += 1
        entry = {
            'timestamp': packet.time,
            'protocol': packet[IP].proto if IP in packet else None,
            'src_ip': packet[IP].src if IP in packet else None,
            'dst_ip': packet[IP].dst if IP in packet else None,
            'size': len(packet)
        }
        if TCP in packet:
            entry.update({'src_port': packet[TCP].sport, 'dst_port': packet[TCP].dport})
        elif UDP in packet:
            entry.update({'src_port': packet[UDP].sport, 'dst_port': packet[UDP].dport})
        else:
            entry.update({'src_port': None, 'dst_port': None})
        self.packets.append(entry)

    def stop_filter(self, packet):
        """Called by scapy.sniff() after every packet to decide whether to stop."""
        return self.counter >= self.max_packets
