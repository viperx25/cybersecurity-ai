import sys
import collections

http_log_path = "http.log"

user_agents = collections.defaultdict(int)
hosts = collections.defaultdict(int)
uris = collections.defaultdict(int)
uri_patterns_with_src = collections.defaultdict(list) # (src_ip, host, uri) -> [timestamps]

long_uris = []
encoded_uris = []

try:
    with open(http_log_path, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            fields = line.strip().split('\t')
            if len(fields) >= 13: # Ensure enough fields for user_agent, host, uri
                ts = fields[0]
                src_ip = fields[2]
                host = fields[10] # This should be host
                uri = fields[8]  # This should be uri
                user_agent = fields[12]

                user_agents[user_agent] += 1
                hosts[host] += 1
                uris[uri] += 1
                uri_patterns_with_src[(src_ip, host, uri)].append(float(ts))

                if len(uri) > 100:
                    long_uris.append(f"{ts} | {src_ip} | {host} | {uri}")
                if '%' in uri: # Simple check for percent encoding
                    encoded_uris.append(f"{ts} | {src_ip} | {host} | {uri}")

except FileNotFoundError:
    print(f"Error: {http_log_path} not found.")
    sys.exit(1)
except Exception as e:
    print(f"Error processing {http_log_path}: {e}")
    sys.exit(1)

print("--- Top 10 User-Agents ---")
for ua, count in sorted(user_agents.items(), key=lambda item: item[1], reverse=True)[:10]:
    print(f"{count}\t{ua}")

print("\n--- Top 10 Hosts ---")
for host, count in sorted(hosts.items(), key=lambda item: item[1], reverse=True)[:10]:
    print(f"{count}\t{host}")

print("\n--- Top 10 URIs ---")
for uri, count in sorted(uris.items(), key=lambda item: item[1], reverse=True)[:10]:
    print(f"{count}\t{uri}")

print("\n--- Long URIs (length > 100) ---")
if long_uris:
    for u in long_uris:
        print(u)
else:
    print("No long URIs found.")

print("\n--- URIs with Percent Encoding ---")
if encoded_uris:
    for u in encoded_uris:
        print(u)
else:
    print("No URIs with percent encoding found.")

print("\n--- Potential HTTP Beaconing (Frequent (src_ip, host, uri) combinations) ---")
beaconing_candidates = []
for (src, h, u), timestamps in uri_patterns_with_src.items():
    if len(timestamps) > 5: # Threshold for "frequent"
        timestamps.sort()
        # Check for somewhat regular intervals
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            # Simple check for regularity: intervals are close to the average
            # This is a basic heuristic; more advanced methods exist.
            is_regular = all(abs(inter - avg_interval) < avg_interval * 0.2 for inter in intervals) # 20% deviation
            if is_regular:
                beaconing_candidates.append(f"{src} | {h} | {u} | Count: {len(timestamps)} | Avg Interval: {avg_interval:.2f}s")
if beaconing_candidates:
    for bc in beaconing_candidates:
        print(bc)
else:
    print("No obvious HTTP beaconing patterns found.")
