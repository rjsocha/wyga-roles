# wyga/maintenance

Periodic maintenance scripts driven by host policy. Each maintenance type
(`docker`, `gitlab-runner`) gets:

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

### GitLab Runner actions

| action | command |
|---|---|
| `cache` | remove every `cache.zip` under `/home/gitlab-runner/cache` |

Only `cache.zip` files are removed, directories stay. The runner saves a
cache into a temporary file and renames it over `cache.zip`, so a job that
is restoring or saving cache during the cleanup is not affected - the
next job without a cache starts from scratch.

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

### Shell runner with growing local cache

Terraform providers pile up in a cache key on every provider bump:

```yaml
maintenance:
  gitlab-runner:
    run:
      - cache
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
