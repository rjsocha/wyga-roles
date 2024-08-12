# Problem

iptables firewall and docker integration

How to update firewall rules (at runtime) using netfilter-persistent package without restarting (reseting) already appiled rules (docker rules).

Please make sure you understand how networking (in context of iptables integration). For referenece:
https://docs.docker.com/engine/network/packet-filtering-firewalls/

When iptables rules are reseted all docker's iptable rules are wipeouted. And to restore them one solution is to restart docker daemon.
But this restarts running containers (alternative option is to use docker's live-restore option - but this brings other problems).


# What this role do?

This role implement this by using such logic:

 - apply master iptables template (generic one)
 - use additional chains (hooks) to apply dynamic rules
 - generate pernament state file for rules (/etc/iptables/rules.v4)
 - dynamicaly apply changed rules at runtime

# Used chains (hooks)

 - FILTER-INPUT-RULES
 - FILTER-FORWARD-RULES
 - FILTER-OUTPUT-RULES
 - NAT-PREROUTING-RULES
 - NAT-POSTROUTING-RULES
 - DOCKER-USER-RULES

# Standard chains

 All chains beside DOCKER-USER-RULES by default block traffic and any rule added to this chains permits traffic.

# DOCKER-USER-RULES

This chain is used to block traffic comming towards docker's containers (by default docker permits any traffic).

