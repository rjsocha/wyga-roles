# wyga/roles

Ansible roles for declarative host management. Each host is described by one
YAML policy file; the roles read it and bring the host to that state. A run
on a host that already matches its policy changes nothing.

Supported systems:

- Debian 12, 13
- Ubuntu 22.04, 24.04, 26.04

## Install

In the `roles` folder of a policy repository:

```
git submodule add <GITURL> wyga
git submodule update --recursive --remote
```

or use a subtree.

## Policy repository

```
host-policy.yaml        playbook
hosts                   inventory
policy/default.yaml     defaults merged into every host
policy/<hostname>.yaml  one file per host
roles/wyga              this repository
```

Playbook:

```yaml
---
- name: "Host Policy"
  gather_facts: false
  hosts: all
  force_handlers: true
  roles:
    - wyga/install/python
    - wyga/host-policy
```

## Example policy

`policy/web1.example.com.yaml`:

```yaml
---
policy:
- hostname: web1.example.com
  network:
    interface:
      - use: static/enp1s0
        ip: 192.0.2.10/24
        gw: 192.0.2.1
        dns: [ 192.0.2.1 ]
  package:
    baseline: vm
    packages:
      - .base
      - nginx-light
  firewall:
    input:
      - allow: icmp
      - allow: ssh
      - allow: http
  setup:
    locale: c/en/cet
    storage:
      lvm:
        lv:
          root:
            vg: system
            size: 16GiB
          swap:
            vg: system
            size: 2GiB
    filesystem:
      swap:
        SWAP:
          device: /dev/system/swap
    audit:
      from: common
  security:
    updates:
      from: common
    restart: {}
  user:
    root:
      authorized:
        - admin
...
```

## Run

```
ansible-playbook -i hosts host-policy.yaml -l web1.example.com --check --diff
ansible-playbook -i hosts host-policy.yaml -l web1.example.com
```

`--check` prints what would change without touching the host.
`wyga/policy-validate` stops the run at the start when a policy uses an
outdated form, with a message naming the new one.

## Roles

Each role has its own `README.md`. The main areas:

| Policy key | Roles |
| --- | --- |
| `network` | `systemd-network`, `hostname` |
| `package` | `apt`, `install-repository`, `install-packages`, `baseline` |
| `firewall` | `firewall` |
| `setup.storage`, `setup.filesystem` | `storage`, `filesystem` |
| `setup.ssh` | `ssh` |
| `setup.monitoring` | `monitoring` |
| `setup.audit` | `audit` |
| `setup.vpn` | `nebula-vpn` |
| `setup.kvm` | `kvm`, `kvm-profile` |
| `setup.ingress` | `ingress` |
| `security.updates` | `updates` |
| `security.restart` | `needrestart` |
| `user` | `user-manager` |
