#!/bin/bash
awk '($13 == "NXDOMAIN") {print $1, $3, $10}' dns.log | sort | uniq -c | sort -rn | head -n 20