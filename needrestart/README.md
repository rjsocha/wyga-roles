# wyga/needrestart

Installs `needrestart`, which reports services, sessions and the kernel
still running old code after an update. By default it only reports.

- Reads `security.restart` of the host policy.
- `wyga/host-policy` runs it after `wyga/monitoring`.

## Quick start

```yaml
policy:
- hostname: host.example.net
  security:
    restart: {}
```

## Policy: `security.restart`

| Key | Meaning |
| --- | --- |
| `mode` | `list` (default): report only; `interactive`: ask; `automatic`: restart services |
| `kernel` | report a running kernel older than the installed one (default `true`) |

## What the role manages

| What | Where |
| --- | --- |
| configuration | `/etc/needrestart/conf.d/50-host-policy.conf`, whole file |
| monitoring flag | `/var/opt/host-policy/needrestart` |

The flag turns on the probe `needrestart` of `check-mk-agent-push` (service "Local Needrestart"); without it the probe prints nothing.

## Behaviour

- **Written before install.** needrestart runs after every apt run,
  including the one that installs it. On Ubuntu its default in the apt
  hook is `automatic`, so the role writes the configuration first.
- `mode: automatic` restarts services after every apt run, the apt runs
  of host-policy included. needrestart itself never restarts `docker*`.

## Reading the result

```sh
needrestart -b
```
