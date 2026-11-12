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
| `maintenance` | `maintenance` | units **needrestart refuses to restart** that this host nevertheless allows the maintenance run to bring up, on top of the role's own table (default: none). A unit needrestart restarts by itself needs no entry - see below |

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

The run is `needrestart -r a` plus the hard cases. needrestart decides for
itself what it restarts and does it; the role handles what needrestart refuses
to touch, and reports what nothing but a reboot or a recreated workload can
fix. Both halves are below.

The role exists only for the case where no reboot is needed, so it checks that
first: with a pending kernel or microcode upgrade, or with a service only a
reboot can fix, it prints the plan and restarts nothing - not even the
`needrestart -r a`. A reboot costs the same downtime and leaves the host in
one consistent state instead of a half restarted one.

```sh
./needrestart-restart -i my -eneedrestart_force=1
```

That is the exception: a host you cannot reboot today, where you still want
the running services off the old libraries.

## Where the decision comes from

Two layers, and the first one is not the role's.

**needrestart restarts what it can.** Its own `$nrconf{override_rc}`
(`/etc/needrestart/needrestart.conf` plus its `conf.d`, read as perl) is a
table of regexes marking the units it refuses; everything else it restarts in
one combined `systemctl restart`. On Debian 13 (needrestart 3.11) it refuses
`dbus*`, `bird`, `network*`, `NetworkManager`, `wpa_supplicant`, `openvpn`,
`*swan`, `getty@*`, `serial-getty@*`, `user@N.service`, `lxc*`, `libvirt*`,
`virtlogd`, `virtlockd`, `docker*`, `apt-daily*`, `unattended-upgrades`,
`cron-*`, `rc-local`, `systemd-logind`, `systemd-nspawn*`, the display
managers and a handful of others. It does **not** refuse `ssh`, `cron`,
`nginx`, `rsyslog`, `polkit`, `containerd`, `zerotier-one`, `knot`,
`systemd-journald`, `systemd-machined`, `systemd-networkd` (the `network*`
regex does not match it), `systemd-resolved`, `systemd-timesyncd` or
`systemd-udevd` - all of those it restarts on its own, and none of them needs
an entry in this role. It also brings itself up to date through its own
`restart.d` helpers: `systemd-manager` is `systemctl daemon-reexec`, and
`systemd-user` signals `SIGRTMIN+25` to every `user@*.service`.

**The role handles what needrestart refuses**, because for those units the
action is not always a plain restart:

| Action | Units | Why |
| --- | --- | --- |
| `restart` | `bird`, `libvirtd`, `unattended-upgrades` | the plain case |
| `reload` | `virtlogd` | `ExecReload` sends `SIGUSR1`, on which virtlogd re-exec()s its binary and keeps all current logs and clients (`man 8 virtlogd`); a restart would cut the log of every running guest |
| restart, but gated | `systemd-logind` | safe unless a session scope has lost its leader and still holds daemons; pulls `unattended-upgrades`, `polkit` and `omd` behind it, below |
| host reboot | `dbus`, the kernel, the microcode | below |
| report only | `apt-daily*`, `SESS` entries, guests on old qemu, a unit restarted while its workload still holds the old binary | below |
| own scan | user managers | needrestart's `SIGRTMIN+25` is not enough, below |

`needrestart_allow` in the role's defaults is the subset of the refused units
every host may bring up, `needrestart_action` says how, `needrestart_gate`
holds a unit back until its precondition is met and `needrestart_follow` names
what has to be try-restarted behind it.

Policy adds to that list with `security.restart.maintenance`, it never takes
anything away from it, and the skip and reboot lists win over both. A refused
unit in neither the table nor the policy is reported and left running, so the
operator can decide and add it. **Adding a unit needrestart already restarts
is a no-op and should not be done** - it duplicates a decision that lives in
needrestart and goes stale there.

### How the plan is built

`needrestart -b -r l` is the machine-readable report, and it lists every unit
on old code without saying what needrestart would do with it - the refusal
lives in the config, not in the report. The split comes from the human output
of `needrestart -r l` (forced to `LC_ALL=C`), which prints three sections:
`Services to be restarted:`, `Service restarts being deferred:` and `Service
restarts being refused by systemd:` (`RefuseManualStop=yes`). The role parses
those into `needrestart_automatic`, `needrestart_deferred` and
`needrestart_refused`, and asserts that together they account for every unit
in the batch report - if a future needrestart changes its output, the run
fails instead of planning from half an answer.

Only the plan depends on that parsing. The execution path does not: it runs
`needrestart -r a`, then reads the report again and works from what is left.

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
- **Sessions (`SESS`).** A login shell on an old binary is the user's to
  solve, by logging in again. A `@ user manager` entry is not: the role
  restarts those itself, below.
- **Guests on outdated qemu binaries.** Only a restart of the guest helps
  (below).
- **A unit that was restarted and is still reported.** The unit is up to date;
  a process of its workload is not, and it sits in the unit's cgroup, so
  needrestart keeps attributing it to the unit. `containerd` is the standing
  case: every running container has a `containerd-shim-runc-v2` of its own,
  started with the binary that was current then and never replaced by a
  restart of containerd - the containers themselves survive the restart
  (`KillMode=process`, `Delegate=yes`), and that is exactly why the shim
  stays. Only recreating the workload replaces it. Structurally the same thing
  as a guest on an old qemu, so the run reports it the same way, on its own
  line, after the second report.

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

`systemd-logind` is the only service whose restart breaks the guard this way,
which is why a logind restart always pulls a `try-restart` of the guard behind
it (below).

## `systemd-logind` is restarted, but only on a clean host

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

So the unit is in the allow list, behind a gate (`needrestart_gate`): the run
first walks the session scopes (below), and if any of them has lost its leader
and still holds daemons, logind is held back and the plan says which scope
blocks it. A host whose session scopes are empty, or whose sessions are all
alive, gets the restart. In `--check` the gate runs too, so the plan already
tells you whether logind will go.

Some things must follow it, whether or not needrestart listed them, because
they hold cached state from the logind they talked to at their own start.
`needrestart_follow` is that table:

- **`unattended-upgrades.service`**, the shutdown guard. It keeps a D-Bus
  proxy to logind and a `delay` inhibitor lock taken through it; after a
  logind restart the lock is broken, and every shutdown, reboot and `virsh
  shutdown` of a guest waits out `InhibitDelayMaxSec` - 30 s on these hosts -
  before it proceeds.
- **`polkit.service`**, which caches the session and seat state it reads from
  logind.
- **`omd.service`**. A Checkmk site started by hand sits in a login session
  scope, so it is exactly what a logind restart can reap; restarting the unit
  afterwards puts the site back in `system.slice`.

Followers are restarted with `systemctl try-restart`, so a unit that was
stopped stays stopped - the run never starts something as a side effect - and
a host that does not have the unit at all is filtered out beforehand with
`systemctl cat`. They run after the unit that pulled them in, and the plan
lists them under their own line.

## User managers

needrestart's own answer for a user manager is `SIGRTMIN+25`, which makes
`systemd --user` re-exec itself, and it sends it in the `-r a` phase whenever
it reports `systemd-user`. That is not enough. Every user manager also
has a `(sd-pam)` child - a forked `systemd-executor` that holds the PAM
session open and waits - and nothing re-executes it, so after a library
upgrade it keeps the deleted mapping for as long as the session lives. On a
lingering user that is forever: a WARN that no reload can clear.

This is maintenance, so the role restarts the unit instead. It walks every
active `user@*.service`, reads the whole cgroup tree of each one, and restarts
the ones holding a process with a deleted `exe` or mapping. The UID comes from
the instance name, so nothing is hardcoded; the whole user slice goes down and
comes back, which means the user's enabled `--user` units return but anything
that user started by hand in `app.slice` does not.

Scanning the whole tree, not just `init.scope`, is deliberate: a user daemon
on an old library (a sync client, an agent) is invisible to needrestart, which
only looks at system services, and the manager restart is what fixes it.

`loginctl terminate-user` is not used for this, and is worth avoiding by hand.
It stops the manager through `exit.target`, and logind starts a lingering
user's manager only at its own startup, on `enable-linger` and on a login - so
the user stays down until someone logs in or the host reboots. `systemctl
restart user@<uid>.service` has none of that problem.

## Daemons in a login session scope

Before it plans anything the role walks `/run/systemd/sessions/*`, and for each
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

`nginx` is the trap, and it is worth knowing even though needrestart owns the
decision for it. `ExecReload` is `nginx -s reload`, a `SIGHUP`: the master
keeps running, and the workers are `fork()`ed from it, so they inherit its
mappings, deleted libraries included. The report does not go away. The live
binary upgrade is the `upgrade` action of `/etc/init.d/nginx` (`SIGUSR2`, wait
for both pid files, `SIGQUIT` to the old master), which the systemd unit does
not have. needrestart restarts the unit, which is the right call of the two it
has; a host that cannot take that needs an entry in its own policy, not a
reload.
