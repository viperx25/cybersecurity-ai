#!/bin/bash
awk 'length($10) > 60 {print $1, $3, $10, length($10)}' dns.log | sort -k4nr | head -n 20