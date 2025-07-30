#!/bin/bash

# define the path to the CSV file containing the list of ports
CSV_FILE="./config/port_list.csv"

# check if the CSV file exists
if [ ! -f "$CSV_FILE" ]; then
  echo "CSV file '$CSV_FILE' not found. Please create the file and add port numbers."
  exit 1
fi

# clear existing OUTPUT chain rules for both IPv4 and IPv6
echo "Clearing existing iptables and ip6tables OUTPUT chain rules..."
iptables -F OUTPUT
ip6tables -F OUTPUT

# read the CSV file and add rules to drop RST packets on the specified ports
echo "Adding rules to drop RST packets on specified ports..."
while IFS=, read -r port
do
  if [ -n "$port" ]; then
    # IPv4 rule
    iptables -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
    echo "Added IPv4 rule to drop RST packets on port $port"
    
    # IPv6 rule
    ip6tables -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
    echo "Added IPv6 rule to drop RST packets on port $port"
  fi
done < "$CSV_FILE"

# save the iptables rules for Ubuntu/Debian
echo "Saving iptables rules..."
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

echo "Rules have been added to drop RST packets on the specified ports for both IPv4 and IPv6."
echo "IPv4 rules saved to /etc/iptables/rules.v4"
echo "IPv6 rules saved to /etc/iptables/rules.v6"
