#!/bin/bash
echo "--- PIR 2: Excessively long domains in dns.log ---"
awk 'length($10) > 60 {print $1, $3, $10, length($10)}' dns.log | sort -k4nr | head -n 20

echo "--- PIR 2: Frequent NXDOMAINs in dns.log ---"
awk '($13 == "NXDOMAIN") {print $3, $10}' dns.log | sort | uniq -c | sort -rn | head -n 20
