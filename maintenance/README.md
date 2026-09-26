# wyga/maintenance

Periodic maintenance scripts driven by host policy. Each maintenance type
(currently `docker`) gets:

- `/opt/maintenance/<type>` - the script, shipped by the role
- `/etc/site/maintenance/<type>` - bash array `MAINTENANCE=(...)` with the
  actions to run, generated from policy
- `maintenance-<type>.service` + `maintenance-<type>.timer` - systemd units

The script runs the actions in the order they are listed. An empty list does
nothing. Removing the type from policy stops the timer and removes all of
the above from the host.

## Policy

```yaml
policy:
- hostname: host.example.com
  maintenance:
    docker:
      schedule: weekly     # default: weekly
      timezone: UTC        # default: UTC
      run:                 # default: [] - nothing
        - image
        - volume
```

### Schedule

All schedules fire at 03:00 in `timezone`.

| schedule | OnCalendar |
|---|---|
| `hourly` | every hour, minute 0 |
| `daily` | every day |
| `weekly` | Sunday |
| `monthly` | 1st day of month |
| `monday` ... `sunday` | that day of week |

`timezone` is any zone known to the host (`timedatectl list-timezones`).
Timers are `Persistent=true` - a run missed while the host was down starts
after boot.

### Docker actions

| action | command |
|---|---|
| `buildkit` | remove `buildx_buildkit_*` containers started more than 12h ago with their `*_state` volumes, and orphaned `*_state` volumes |
| `image` | `docker image prune --all --force` |
| `volume` | `docker volume prune --all --force` |
| `anonymous-volumes` | `docker volume prune --force` - anonymous volumes only, named volumes stay |
| `system` | `docker system prune --all --force --volumes` |
| `builder` | `docker builder prune --all --force` |
| `container` | `docker container prune --force` |
| `network` | `docker network prune --force` |

An unknown action fails the playbook.

## Examples

### CI host with remote buildx builders

```yaml
maintenance:
  docker:
    schedule: saturday
    timezone: Europe/Warsaw
    run:
      - buildkit
      - image
      - volume
      - builder
```

### Weekly full cleanup

```yaml
maintenance:
  docker:
    run:
      - system
      - volume
```

### Disable

Remove `maintenance.docker` from policy. An empty `run` keeps the timer but
the script does nothing:

```yaml
maintenance:
  docker:
    run: []
```

## Manual run

```bash
systemctl start maintenance-docker.service
journalctl -u maintenance-docker.service
```
