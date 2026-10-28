# Problem

iptables firewall and docker integration

How to update firewall rules (at runtime) using netfilter-persistent package without restarting (reseting) already appiled rules (docker rules).

Please make sure you understand how networking works with docker (in context of iptables integration). For referenece:
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

# Profile generic (firewall.profile: generic)

A plain host without Docker or KVM: the `docker` skeleton without the
`DOCKER-*` chains - INPUT filtered (conntrack, `lo`, `FILTER-INPUT-RULES`,
reject), FORWARD dropped unless a rule allows it, the usual `*-RULES` hooks.

`firewall.chains` declares external chains: the role creates them and hooks
them in, but never flushes or fills them - a service owns their content
(e.g. a VPN updown script). Fixed hook points:

 - `filter` - jumped to from FORWARD, after `FILTER-FORWARD-RULES`
 - `nat` - jumped to from POSTROUTING, after `NAT-POSTROUTING-RULES`
 - `mangle` - jumped to from FORWARD (the mangle table is written only when
   this list is set)

```yaml
firewall:
  profile: generic
  chains:
    filter: [ VPN-FWD ]
    nat: [ VPN-NAT ]
    mangle: [ VPN-MSS ]
  restart:
    - strongswan-starter.service
```

The chains are part of the master template: changing the list restarts the
firewall, which empties them - list the owning service in `firewall.restart`
so it refills them.

# Site profiles (firewall.profile: <name>)

Built-in profiles: `docker` (default), `kvm` and `generic`. A site can add its own
profile without changing the role - `firewall.profile: <name>` first looks for

 - `site/<host_policy_site>/firewall/profile/<name>/rules`

in the playbook directory and falls back to the built-in templates. A site
profile holds the same files as a built-in one: `rules` (master, also
rendered into `/etc/iptables/rules.v4` with `firewall_rules: true`) and
`rules-apply` (runtime update of the `*-RULES` chains). Both may include the
built-in rule renderers, e.g. `{% include "firewall/generic/rules-filter" %}`.

# SSH source lists (allow: ssh/<name>)

`allow: ssh` permits SSH (tcp/22) from anywhere (0.0.0.0/0).

`allow: ssh/<name>` loads allowed sources from a file in the playbook directory. First found wins (no merging):

 - `site/<host_policy_site>/firewall/ssh/<hostname>/<name>.yaml`
 - `site/<host_policy_site>/firewall/ssh/<hostname>/<name>`
 - `site/<host_policy_site>/firewall/ssh/<name>.yaml`
 - `site/<host_policy_site>/firewall/ssh/<name>`

`<hostname>` is `host.hostname` - a per-host file overrides the shared one with the same name.

Two file formats are supported (detected by content, not by extension).

Simple list - one rule, no comment:

```yaml
---
hosts:
  - 192.0.2.10
  - 192.0.2.0/28
```

Extended list - one rule per entry. `src` is required, `dst`, `iface` and `comment` are optional. `src` and `dst` accept a single address or a list:

```yaml
---
firewall:
  allow:
    - comment: "internal"
      src: 100.100.96.0/20
    - comment: "VPN Pool"
      src: [192.168.0.0/20, 192.168.16.0/20]
      iface: eth0
      dst: 198.18.4.0/22
    - src: 1.1.1.1/32
```

Policy:

```yaml
firewall:
  input:
    - allow: ssh/bastions
```

Generated rules:

```
-A FILTER-INPUT-RULES -m tcp -p tcp --dport 22 -s 100.100.96.0/20 -m comment --comment "internal" -j ACCEPT
-A FILTER-INPUT-RULES -m tcp -p tcp -i eth0 --dport 22 -s 192.168.0.0/20,192.168.16.0/20 -d 198.18.4.0/22 -m comment --comment "VPN Pool" -j ACCEPT
-A FILTER-INPUT-RULES -m tcp -p tcp --dport 22 -s 1.1.1.1/32 -j ACCEPT
```
