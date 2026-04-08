
import sys
import collections

def analyze_http_log(log_file):
    post_requests = collections.defaultdict(list)
    
    with open(log_file, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            
            fields = line.strip().split('	')
            
            if len(fields) > 8: # Ensure there are enough fields
                timestamp = float(fields[0])
                method = fields[7]
                host = fields[8]
                uri = fields[9]
                
                if method == 'POST':
                    post_requests[host].append((timestamp, uri))

    findings = []
    
    for host, requests in post_requests.items():
        if len(requests) < 5: # Require at least 5 POSTs to consider it beaconing
            continue

        # Sort requests by timestamp
        requests.sort()

        # Check for regular intervals
        intervals = []
        for i in range(1, len(requests)):
            interval = requests[i][0] - requests[i-1][0]
            intervals.append(interval)

        # Basic check for regularity: if most intervals are similar
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            # Consider as beaconing if 80% of intervals are within 20% of the average
            regular_intervals = [i for i in intervals if abs(i - avg_interval) / avg_interval < 0.2]
            
            if len(regular_intervals) / len(intervals) > 0.8:
                start_time = requests[0][0]
                end_time = requests[-1][0]
                findings.append(f"{start_time}-{end_time} | {host} | HTTP POST | Consistent HTTP POST beaconing to {host} (avg interval: {avg_interval:.2f}s) | Command and Control (T1071) | Medium")
                
    return findings

if __name__ == "__main__":
    findings = analyze_http_log("http.log")
    for finding in findings:
        print(finding)
