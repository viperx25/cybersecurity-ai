
import sys
from collections import defaultdict

dns_log_path = "dns.log"

domains_count = defaultdict(int)

with open(dns_log_path, 'r') as f:
    for line in f:
        if line.startswith('#'):
            continue
        fields = line.strip().split('\t')
        if len(fields) > 9: # Ensure 'query' field exists
            query = fields[9]
            domains_count[query] += 1

print("--- Top 20 Queried Domains ---")
sorted_domains = sorted(domains_count.items(), key=lambda item: item[1], reverse=True)
for domain, count in sorted_domains[:20]:
    print(f"Domain: {domain}, Count: {count}")

print("\n--- Rare Domains (Count <= 2) ---")
rare_domains = []
for domain, count in sorted_domains:
    if count <= 2:
        rare_domains.append((domain, count))
    else:
        # Since the list is sorted by count, once we pass the rare domains,
        # we can stop iterating for this specific check.
        break

if rare_domains:
    for domain, count in rare_domains:
        print(f"Domain: {domain}, Count: {count}")
else:
    print("No rare domains found.")
