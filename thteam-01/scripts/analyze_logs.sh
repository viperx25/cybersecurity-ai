#!/bin/bash

echo "--- HTTP Log Analysis (User Agents) ---"
awk -F'\t' '{print $13}' http.log | sort | uniq -c | sort -rn | head -10

echo "--- HTTP Log Analysis (Request Methods) ---"
awk -F'\t' '{print $8}' http.log | sort | uniq -c | sort -rn | head -10

echo "--- HTTP Log Analysis (Hosts) ---"
awk -F'\t' '{print $9}' http.log | sort | uniq -c | sort -rn | head -10

echo "--- HTTP Log Analysis (URIs) ---"
awk -F'\t' '{print $10}' http.log | sort | uniq -c | sort -rn | head -10

echo "--- HTTP Log Analysis (Suspicious User Agents) ---"
grep -E "(curl|Wget|python|ruby|perl)" http.log || echo "No suspicious user agents found."

echo "--- Files Log Analysis (MIME Types) ---"
awk -F'\t' '{print $11}' files.log | sort | uniq -c | sort -rn | head -10

echo "--- Files Log Analysis (Filenames) ---"
awk -F'\t' '{print $12}' files.log | sort | uniq -c | sort -rn | head -10

echo "--- Weird Log Content ---"
cat weird.log
