import sys

def analyze_conn_log(log_file):
    src_ip_to_dest_ips = {}
    src_ip_to_dest_ports = {}

    with open(log_file, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            
            fields = line.strip().split('\t')
            if len(fields) > 12:
                conn_state = fields[11]  # conn_state is column 12 (index 11)
                
                if conn_state in ['RSTO', 'RSTR', 'S0', 'S1']:
                    src_ip = fields[2]  # id.orig_h is column 3 (index 2)
                    dest_ip = fields[4] # id.resp_h is column 5 (index 4)
                    dest_port = fields[5] # id.resp_p is column 6 (index 5)

                    if src_ip not in src_ip_to_dest_ips:
                        src_ip_to_dest_ips[src_ip] = set()
                    src_ip_to_dest_ips[src_ip].add(dest_ip)

                    if src_ip not in src_ip_to_dest_ports:
                        src_ip_to_dest_ports[src_ip] = set()
                    src_ip_to_dest_ports[src_ip].add(dest_port)

    print("\n--- Top 10 Source IPs by Distinct Failed Destination IPs ---")
    sorted_ips_by_dest_ips = sorted(src_ip_to_dest_ips.items(), key=lambda item: len(item[1]), reverse=True)
    for ip, dest_ips in sorted_ips_by_dest_ips[:10]:
        print(f"IP: {ip}, Distinct Failed Destination IPs: {len(dest_ips)}")

    print("\n--- Top 10 Source IPs by Distinct Failed Destination Ports ---")
    sorted_ips_by_dest_ports = sorted(src_ip_to_dest_ports.items(), key=lambda item: len(item[1]), reverse=True)
    for ip, dest_ports in sorted_ips_by_dest_ports[:10]:
        print(f"IP: {ip}, Distinct Failed Destination Ports: {len(dest_ports)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_scanning.py <conn_log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    analyze_conn_log(log_file)