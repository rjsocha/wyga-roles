# wyga/marker

Writes or removes a marker file in `/var/opt/host-policy`, the state
directory of host-policy. Roles use markers to tell other components what
the policy enabled, for example the probes of `check-mk-agent-push`,
which stay silent without their marker.

- Included by other roles, never from the policy.
- Creates `/var/opt/host-policy` as `root:root 0700`.

## Use

```yaml
- include_role:
    name: wyga/marker
  vars:
    marker: audit            # /var/opt/host-policy/audit
    # marker_state: absent   # removes the marker
```

| Variable | Meaning |
| --- | --- |
| `marker` | file name inside the state directory, no `/` |
| `marker_state` | `present` (default) or `absent` |
| `marker_content` | content of the file, `# managed by host-policy` by default |
| `marker_mode` | mode of the file, `0644` by default |
| `marker_dir` | state directory, `/var/opt/host-policy` |

The result of the write is registered as `marker_written`
(`marker_written.changed` tells a first write).

## Consumers

| Role | Marker | Used by |
| --- | --- | --- |
| `wyga/host-policy` | `policy` (`0600`, hostname) | the check that the host runs its own policy; first write reboots |
| `wyga/host-policy` | `static-ip` (`0600`, address) | the move to a static address |
| `wyga/baseline` | `baseline` (`0400`, package report), `firstboot` (removed) | baseline runs once |
| `wyga/audit` | `audit` | probe `audit` ("Local Audit") |
| `wyga/needrestart` | `needrestart` | probe `needrestart` ("Local Needrestart") |
| `wyga/updates` | `updates` | probe `unattended-upgrades` ("Local Unattended Upgrades") |
