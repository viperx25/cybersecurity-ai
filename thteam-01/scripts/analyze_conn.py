
import sys
from collections import defaultdict

conn_log_path = "conn.log"

dest_ports = defaultdict(int)
source_ips = defaultdict(int)
long_duration_conns = []

with open(conn_log_path, 'r') as f:
    for line in f:
        if line.startswith('#'):
            continue
        fields = line.strip().split('\t')
        if len(fields) > 9: # Ensure there are enough fields
            try:
                # ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration
                ts = fields[0]
                orig_h = fields[2]
                orig_p = fields[3]
                resp_h = fields[4]
                resp_p = fields[5]
                duration = float(fields[8])
                conn_state = fields[11]

                dest_ports[resp_p] += 1
                source_ips[orig_h] += 1

                if duration > 60: # Threshold for long duration
                    long_duration_conns.append((ts, orig_h, orig_p, resp_h, resp_p, duration, conn_state))
            except ValueError:
                # Handle cases where duration might not be a float (e.g., '-')
                continue

print("--- Top 20 Destination Ports ---")
sorted_ports = sorted(dest_ports.items(), key=lambda item: item[1], reverse=True)
for port, count in sorted_ports[:20]:
    print(f"Port: {port}, Count: {count}")

print("\n--- Top 20 Source IPs by Connection Count ---")
sorted_ips = sorted(source_ips.items(), key=lambda item: item[1], reverse=True)
for ip, count in sorted_ips[:20]:
    print(f"IP: {ip}, Count: {count}")

print("\n--- Top 20 Long Duration Connections (> 60s) ---")
# Sort by duration in descending order
long_duration_conns.sort(key=lambda x: x[5], reverse=True)
for conn in long_duration_conns[:20]:
    print(f"Timestamp: {conn[0]} | Src: {conn[1]}:{conn[2]} | Dst: {conn[3]}:{conn[4]} | Duration: {conn[5]} | State: {conn[6]}")
