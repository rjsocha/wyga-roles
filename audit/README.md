# wyga/audit

Configures the Linux audit subsystem of a host from its policy: installs
`auditd`, writes `/etc/audit/auditd.conf` as a whole and owns
`/etc/audit/rules.d/`.

- Reads `setup.audit` of the host policy.
- `wyga/host-policy` runs it after `wyga/monitoring`.

## Quick start

```yaml
policy:
- hostname: host.example.net
  setup:
    audit:
      from: common
      mode: merge
      rules:
        - -w /etc/ssh-pool -p wa -k ssh-keys
```

`common` records every program started from a login session (ssh,
console) and keeps 10 logs of 50 MB.

## Policy: `setup.audit`

| Key | Meaning |
| --- | --- |
| `from` | template to start from; without it only the policy is used |
| `mode` | `use` (default): a key of the policy replaces the key of the template; `merge`: maps are merged, the rules of the policy come before the rules of the template |
| `config` | keys of `auditd.conf` that differ from the defaults of the distribution |
| `kernel` | `buffer` (`-b`, 8192), `backlog_wait_time` (60000), `failure` (`-f`, 1) |
| `rules` | audit rules, one `auditctl` rule per item |

### Templates

`from: <name>` is looked up in this order:

| Where | What for |
| --- | --- |
| `site/<host_policy_site>/audit/<name>` | local templates of a site |
| `audit/<name>` of the role | templates shipped with the role (`common`) |

A template is a YAML file with the key `audit` holding `config`, `kernel`
and `rules`.

### `config`

`auditd.conf` is rendered from the defaults of the distribution
(`audit/conf/<distribution>/<version>` of the role) with `config` on top.
The versions of auditd differ in the keys they accept, and auditd does not
start with a key it does not know (`report_interval` exists from 4.1 on).
A key that the distribution does not know stops the role before anything
is written.

| Platform | auditd |
| --- | --- |
| Debian 12 | 3.0.9 |
| Debian 13 | 4.0.2 |
| Ubuntu 24.04 | 3.1.2 |
| Ubuntu 26.04 | 4.1.2 |

Another platform stops the role. A new one is a new file below
`audit/conf/`, taken from the default `auditd.conf` of its package.

## What the role manages

| What | Where |
| --- | --- |
| configuration | `/etc/audit/auditd.conf`, whole file |
| base rules (`-D`, `-b`, `--backlog_wait_time`, `-f`) | `/etc/audit/rules.d/10-host-policy-base.rules` |
| rules of the policy | `/etc/audit/rules.d/50-host-policy.rules` |
| monitoring flag | `/var/opt/host-policy/audit` |

The flag turns on the probe `audit` of `check-mk-agent-push` (service "Local Audit"); without it the probe prints nothing.

## Behaviour

- **Exclusive.** `/etc/audit/rules.d/` holds only the two files of the
  role; anything else, the `audit.rules` of the package included, is
  removed.
- **Reload.** A changed `auditd.conf` restarts auditd with `service auditd
  restart` (the unit refuses `systemctl restart`); the role then checks
  that auditd runs. Changed rules are loaded with `augenrules --load`.
- **Not immutable.** The role never sets `-e 2`, so rules can change
  without a reboot.
- `/etc/audit/plugins.d/` is left as the package installs it.

## Reading the log

```sh
ausearch --input-logs -k session-exec -i
ausearch --input-logs -k session-exec -i --session <ses>
```

`--input-logs` is needed when `ausearch` runs without a terminal (for
example `ssh host ausearch ...`); without it it reads stdin and finds
nothing. The `ses=` of a record is the logind session; the `sshd` entry
of that session names the key that logged in.
