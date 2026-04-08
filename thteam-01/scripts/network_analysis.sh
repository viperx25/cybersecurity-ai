#!/bin/bash

echo "--- High-Port Connections (conn.log) ---"
tail -n +2 conn.log | awk '$6 > 1024 {print $1, $5, $6, $7}' | sort | uniq -c | sort -rn | head -20

echo "--- Protocol Counts (conn.log) ---"
tail -n +2 conn.log | awk '{print $7}' | sort | uniq -c | sort -rn

echo "--- High-Volume NXDOMAINs (dns.log) ---"
tail -n +2 dns.log | awk '$16 == "NXDOMAIN" {print $1, $10}' | sort | uniq -c | sort -rn | head -20

echo "--- Long DNS Queries (dns.log) ---"
tail -n +2 dns.log | awk 'length($10) > 30 {print $1, $10}' | sort | uniq | head -20
