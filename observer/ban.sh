#!/bin/bash

# define the path to the CSV file containing the list of ports
CSV_FILE="./config/port_list.csv"

# check if the CSV file exists
if [ ! -f "$CSV_FILE" ]; then
  echo "CSV file '$CSV_FILE' not found. Please create the file and add port numbers."
  exit 1
fi

# clear existing OUTPUT chain rules
iptables -F OUTPUT

# read the CSV file and add rules to drop RST packets on the specified ports
while IFS=, read -r port
do
  if [ -n "$port" ]; then
    iptables -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
    echo "Added rule to drop RST packets on port $port"
  fi
done < "$CSV_FILE"

# save the iptables rules
# CentOS/RHEL
service iptables save

# Debian/Ubuntu
# iptables-save > /etc/iptables/rules.v4

echo "Rules have been added to drop RST packets on the specified ports."
