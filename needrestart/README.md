# wyga/needrestart

Two roles around `needrestart`, which reports services, sessions, the kernel
and the CPU microcode still running old code after an update.

| Role | When it runs | What it does |
| --- | --- | --- |
| `wyga/needrestart/configure` | every policy run, from `wyga/host-policy` | installs `needrestart`, writes its configuration, sets the monitoring flag |
| `wyga/needrestart/maintenance` | by hand, from `./needrestart-restart` | reads the report and restarts what the policy allows |

The split exists because the two have nothing in common at runtime: the first
one brings the host to the described state, the second one is an adhoc
post-upgrade action an operator starts, like `./apt-upgrade`.

Status: `configure` is the former `wyga/needrestart`, moved unchanged.

## Policy: `security.restart`

```yaml
policy:
- hostname: host.example.net
  security:
    restart:
      mode: list
      kernel: true
      maintenance:
        - zerotier-one
```

| Key | Read by | Meaning |
| --- | --- | --- |
| `mode` | `configure` | `list` (default): report only; `interactive`: ask; `automatic`: restart services |
| `kernel` | `configure` | report a running kernel older than the installed one (default `true`) |
| `maintenance` | `maintenance` | services this host allows the maintenance run to restart, on top of the role's own table (default: none) |

# wyga/needrestart/configure

Installs `needrestart`. By default it only reports.

- Reads `security.restart` of the host policy.
- `wyga/host-policy` runs it after `wyga/monitoring`.

## Quick start

```yaml
policy:
- hostname: host.example.net
  security:
    restart: {}
```

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

# wyga/needrestart/maintenance

An adhoc action: restart what still runs old code, without rebooting the
host. Started by hand on a named host, never from a policy run and never
from the apt hook.

```sh
./needrestart-restart -i my --check              # the plan
./needrestart-restart -i my                      # do it
./needrestart-restart -i host.example.net,       # one host
```

The script is an `ansible-playbook` shebang, like `./apt-upgrade`, so every
option of `ansible-playbook` works: `-i` for the inventory, `-l` to limit it,
`--check` for the plan.

`--check` is the plan: the role prints what it would restart, what it skips
and why, and changes nothing. The task that reads the report runs with
`check_mode: false`, otherwise there would be nothing to plan from.

## Scope

Services that can be brought up to date without rebooting the host. Nothing
else. A reboot is the operator's decision.

The role exists only for the case where no reboot is needed, so it checks that
first: with a pending kernel or microcode upgrade, or with a service only a
reboot can fix, it prints the plan and restarts nothing. A reboot costs the
same downtime and leaves the host in one consistent state instead of a half
restarted one.

```sh
./needrestart-restart -i my -eneedrestart_force=1
```

That is the exception: a host you cannot reboot today, where you still want
the running services off the old libraries.

## Where the decision comes from

The role carries its own table of what a service needs, because the action
is not always a restart:

| Action | Examples | Why |
| --- | --- | --- |
| `restart` | `ssh`, `cron`, `rsyslog`, `polkit`, `nginx`, `libvirtd`, `bird`, `knot`, `systemd-journald`, `systemd-machined`, `systemd-networkd`, `systemd-resolved`, `systemd-timesyncd`, `systemd-udevd`, `unattended-upgrades` | the plain case |
| `reload` | `virtlogd` | `ExecReload` sends `SIGUSR1`, on which virtlogd re-exec()s its binary and keeps all current logs and clients (`man 8 virtlogd`); a restart would cut the log of every running guest |
| own command | `systemd-manager`, `systemd-user` | not services: `systemctl daemon-reexec` and `SIGRTMIN+25` to every `user@*.service`, the same thing needrestart's own `restart.d` scripts do |
| host reboot | `dbus`, the kernel, the microcode | below |
| report only | `apt-daily*`, `systemd-logind`, `SESS` entries | below |

`needrestart_allow` in the role's defaults is what every host may restart on
its own: the fifteen services above plus `virtlogd`, `systemd-manager` and
`systemd-user`. Restarting `systemd-machined` keeps the registered machines:
it reads them back from `/run/systemd/machines/`, verified on a host with
eight libvirt guests.

Policy adds to that list with `security.restart.maintenance`,
it never takes anything away from it, and the skip and reboot lists win over
both. A service in neither the table nor the policy is reported and left
running, so the operator can decide and add it.

needrestart's own `$nrconf{override_rc}` is not the source of truth here. It
already says no to `bird`, `docker`, `libvirt`, `virtlogd`, `systemd-logind`,
`unattended-upgrades`, `apt-daily*` and `dbus`, which is why these are
exactly the ones left over after an `automatic` run, and why the table has to
exist.

## Why some things are only reported

- **`dbus`.** Reported as needing a host reboot, together with the kernel and
  the microcode. There is a script that restarts it in place
  (`/etc/needrestart/restart.d/dbus.service`: `loginctl terminate-user` on
  every logind user, then dbus, then every active reverse dependency and
  everything with a `BusName=`, all inside a transient `restart-dbus` unit so
  it survives killing the session it runs in). Three reasons not to use it:
  that session is ours, so Ansible would lose the connection and never learn
  the result; the cascade is computed at runtime, so `--check` could not show
  a plan; and a cascade of service restarts is a less certain outcome than a
  reboot, which costs the same downtime and leaves nothing half-restarted.
- **`apt-daily`, `apt-daily-upgrade`.** These are the apt runs themselves.
  needrestart only ever lists running processes, so seeing one of them means
  an upgrade is in flight, and the role refuses to run at all (below).
- **Kernel (`KSTA`), microcode (`UCSTA`).** Only a reboot helps.
- **Sessions (`SESS`).** Only the user can help, by logging in again.
- **Guests on outdated qemu binaries.** Only a restart of the guest helps
  (below).

## Outdated qemu guests

A `qemu-system-*` process keeps the binaries it was started with, so after a
qemu or library upgrade every guest that has been running since before the
upgrade still executes the old code. Rebooting the guest from the inside does
not change that: the process stays. Only `virsh shutdown` plus `virsh start`,
or a migration, replaces it.

needrestart knows this, but prints it only in its interactive output - the
list is behind `unless($opt_p || $opt_b)` and has no `$nrconf{}` switch - so
the batch report the role reads says nothing about guests. The role therefore
looks for them itself: it collects the PIDs from every `cgroup.procs` below
`/sys/fs/cgroup/machine.slice/machine-qemu*.scope` (on cgroup v2 the process
sits in the `libvirt` child of the scope, not in the scope itself), keeps the
ones whose command line contains `qemu-system`, and reports a guest when its
`/proc/<pid>/exe` is gone or `/proc/<pid>/maps` still carries a deleted
mapping. The mappings needrestart ignores are ignored here too: `memfd:`,
`SYSV`, `/dev`, `/run`, `/tmp`, `[aio]`, `drm` and the `/#NNN` form.

The guest name comes from qemu's own `-name guest=<name>` argument, which is
the libvirt domain name, so it can be pasted straight into `virsh`.

The same two facts reach Checkmk from the `needrestart` local check, which
emits a second service, `Local Needrestart VM`, on hosts that have a
`machine.slice`.

## It refuses to run during an apt run

Before anything else the role checks `apt-daily.service`,
`apt-daily-upgrade.service` and `/var/run/unattended-upgrades.pid`, and fails
if any of them says an upgrade is in flight. Restarting services in the middle
of a dpkg transaction is wrong on its own, and it is also what makes
`unattended-upgrades.service` safe to restart here: on `SIGTERM` its guard
takes the apt lock and, finding it free, exits at once
(`unattended-upgrade-shutdown`, `iter()`). With the lock held it would instead
signal the running `unattended-upgrade` and wait for it, up to
`TimeoutStopSec=1800`, killing the upgrade. needrestart blacklists the unit
because needrestart itself runs from the apt hook, which is exactly the case
this role excludes.

One trap found the hard way: the guard takes a `delay` inhibitor lock at
startup and watches logind over a cached dbus proxy. Restart it and then
restart `systemd-logind` under it, and that proxy stops answering;
`is_preparing_for_shutdown()` swallows the exception and keeps returning
false, so the guard never releases the lock. Every shutdown of that host then
waits out `InhibitDelayMaxSec`, which unattended-upgrades raises to 30 seconds
in a logind drop-in, and a second `reboot` in that window is refused with
"Action reboot already in progress". A fresh `systemctl restart
unattended-upgrades` clears it.

This is why `systemd-logind` is not in the allow list, and it is the only
service whose restart can break the guard this way.

## Why `systemd-logind` is not restarted

Not for the reason needrestart blacklists it. Active sessions do survive: the
unit has `FileDescriptorStoreMax=768`, so logind hands the session descriptors
to PID 1 before it exits and takes them back on start.

What does not survive is a *stale* session scope. After a restart logind
reconciles its state and releases sessions it no longer tracks, and systemd
then stops their scopes, killing every process inside. Anything started by
hand in an old login session lives there. On 2026-11-07 this stopped a
Checkmk site on a monitoring host: its daemons sat in a days-old
`session-2057.scope`, and `omd.service`, being a oneshot, reported `active`
while the site was dead.

## Daemons in a login session scope

At the end of every run the role walks `/run/systemd/sessions/*`, and for each
session compares the processes in its scope against a list of interactive
commands, skipping the scope the run itself sits in. What is left is a daemon
that was started by hand from a shell, so it lives in that session's scope and
dies with it. `LEADER GONE` marks the dangerous shape: the session that opened
it is long closed, only the daemons are left.

That is how a Checkmk site was lost on 2026-11-07: `omd start` had been run
over ssh, so the site sat in a days-old session scope. OMD has no systemd
integration of its own, so the unit is the only thing that puts the site in
`system.slice`: `systemctl restart omd`, not `omd restart`. In general, start
such a thing from its unit or with
`systemd-run --slice=system.slice --unit=<name>`.

A signal to a running daemon never moves it between cgroups, so `nginx -s
reload` and the like are not affected; only starting a process is.

## A reload is not always enough

`nginx` is the trap. `ExecReload` is `nginx -s reload`, a `SIGHUP`: the master
keeps running, and the workers are `fork()`ed from it, so they inherit its
mappings, deleted libraries included. The report does not go away. The live
binary upgrade is the `upgrade` action of `/etc/init.d/nginx` (`SIGUSR2`, wait
for both pid files, `SIGQUIT` to the old master), which the systemd unit does
not have. The table therefore says `restart` for nginx; a richer policy can be
added when a host actually needs it.
