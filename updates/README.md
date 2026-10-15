# wyga/updates

Installs updates of a host on its own with `unattended-upgrades`, from
the origins its policy names. The host is never rebooted.

- Reads `security.updates` of the host policy.
- `wyga/host-policy` runs it after `wyga/needrestart`.

## Quick start

```yaml
policy:
- hostname: host.example.net
  security:
    updates:
      from: common
```

`common` installs security updates of the distribution only.

## Policy: `security.updates`

| Key | Meaning |
| --- | --- |
| `from` | template to start from; without it only the policy is used |
| `mode` | `use` (default): a key of the policy replaces the key of the template; `merge`: lists are merged, the items of the policy come before the items of the template |
| `origins` | where updates come from: `security`, `updates` or an `Origins-Pattern` of unattended-upgrades (`origin=Docker`) |
| `blacklist` | packages never upgraded (`Package-Blacklist`, regular expressions) |

### Origins

| Name | Debian | Ubuntu |
| --- | --- | --- |
| `security` | `<codename>-security` | `<codename>-security` |
| `updates` | point releases and `<codename>-updates` | `<codename>-updates` |

The patterns are in `updates/origins/<distribution>` of the role. Another
distribution stops the role. Anything with `=` is passed to
unattended-upgrades as it is.

### Templates

`from: <name>` is looked up in this order:

| Where | What for |
| --- | --- |
| `site/<host_policy_site>/updates/<name>` | local templates of a site |
| `updates/<name>` of the role | templates shipped with the role (`common`) |

A template is a YAML file with the key `updates` holding `origins` and
`blacklist`.

## What the role manages

| What | Where |
| --- | --- |
| schedule (`APT::Periodic`) | `/etc/apt/apt.conf.d/20auto-upgrades`, whole file |
| configuration | `/etc/apt/apt.conf.d/50unattended-upgrades`, whole file |
| timers | `apt-daily.timer`, `apt-daily-upgrade.timer`: enabled and started |
| monitoring flag | `/var/opt/host-policy/updates` |

The flag turns on the probe `unattended-upgrades` of `check-mk-agent-push` (service "Local Unattended Upgrades"); without it the probe prints nothing.

## Behaviour

- **No reboot.** `Automatic-Reboot` is always `false`; a pending reboot is
  left to the operator.
- **Checked.** After writing the files the role reads the configuration
  apt really uses (`apt-config dump`) and stops when it holds other
  origins than the policy, for example `Allowed-Origins` from a file it
  does not manage.
- The Ubuntu installer leaves
  `/etc/apt/apt.conf.d/zzzz-temp-installer-unattended-upgrade` behind,
  with its own origins; the role removes it.
- Updates run at the time of `apt-daily-upgrade.timer` of the
  distribution.

## Reading the log

```sh
cat /var/log/unattended-upgrades/unattended-upgrades.log
unattended-upgrade --dry-run -d
```
