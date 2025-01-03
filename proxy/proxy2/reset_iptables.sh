#!/bin/bash

# Flush all rules in the filter table
iptables -F

# Flush all rules in the nat table
iptables -t nat -F

# Flush all rules in the mangle table
iptables -t mangle -F

# Flush all rules in the raw table
iptables -t raw -F

# Flush all rules in the security table
iptables -t security -F

# Delete all user-defined chains
iptables -X

# Zero all packet and byte counters
iptables -Z

# Set default policies to ACCEPT
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT



echo "All iptables rules have been cleared and default policies set to ACCEPT."
