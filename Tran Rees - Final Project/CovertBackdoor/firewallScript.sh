#!/bin/sh
KNOCK_PORT_1=5432
KNOCK_PORT_2=1234
KNOCK_PORT_3=3425
PORT_TO_OPEN=10022


iptables -F
iptables -X
iptables -Z

#  Allows all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
iptables -A INPUT -s 127.0.0.0/8 -j ACCEPT

#  Accepts all established inbound connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#  Allows all outbound traffic
#  You can modify this to only allow certain traffic
iptables -A OUTPUT -j ACCEPT

# Allows HTTP and HTTPS connections from anywhere (the normal ports for websites)
#iptables -A INPUT -p tcp --dport 80 -j ACCEPT
#iptables -A INPUT -p tcp --dport 443 -j ACCEPT

#  Allows SSH connections
#  Below is a three port knock which will allow a new ssh session. Client must 'knock' on ports 3820, 5446, and 3015 first. Each knock has a 15 second window before the user has to start over.
#  After the knocking is complete the established connection rule comes into place and this won't be tested.
iptables -A INPUT -p udp --dport $KNOCK_PORT_1 -m recent --set --rsource --name SSH_AUTH_KNOCK1 -m limit --limit 15/min -j LOG --log-prefix "ssh knock 1 " --log-level 7
iptables -A INPUT -p udp --dport $KNOCK_PORT_2 -m recent --rcheck --rsource --seconds 15 --name SSH_AUTH_KNOCK1 -m recent --set --rsource --name SSH_AUTH_KNOCK2 -m limit --limit 15/min -j LOG --log-prefix "ssh knock 2 " --log-level 6
iptables -A INPUT -p udp --dport $KNOCK_PORT_3 -m recent --rcheck --rsource --seconds 15 --name SSH_AUTH_KNOCK2 -m recent --set --rsource --name SSH_AUTH -m limit --limit 15/min -j LOG --log-prefix "ssh knock 3 " --log-level 6
iptables -A INPUT -p tcp --dport $PORT_TO_OPEN -m state --state NEW -m recent --rcheck --rsource --seconds 100 --name SSH_AUTH -j ACCEPT
iptables -A INPUT -p udp --dport $PORT_TO_OPEN -m state --state NEW -m recent --rcheck --rsource --seconds 100 --name SSH_AUTH -j ACCEPT

# Allow ping
#-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Deny Ping
iptables -A INPUT -p icmp -j DROP

# log iptables denied calls
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Reject all other inbound - default deny unless explicitly allowed policy
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP

