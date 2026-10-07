# wyga/job

Installs the scheduled jobs of a host from its policy: a program, the
systemd service and timer that run it, and the parameters and
configuration files it reads. The role guarantees that a job of the policy
is installed and that nothing else is; what the program does is its own
business.

- Reads the top-level key `job` of the host policy.
- `wyga/host-policy` runs it last, after the kits, so everything the
  policy and the kits set up exists before a timer is started.
- It always runs, also on a host without `job`: that is how the jobs taken
  off a policy are removed.
- Alone: the playbook `job-config` (`load-policy`, `load-confidential`,
  `wyga/job`).

## Quick start

```yaml
policy:
- hostname: db1.example.net
  job:
    db-dump:
      script: dump
      packages:
        - zstd
      timer:
        calendar: "*-*-* 04:30"
        persistent: true
      timeout: 1h
      env:
        DUMP_TARGET: backup
        DUMP_DB:
          - shop
          - blog
      config:
        - config
```

With the files `site/job/db1.example.net/file/db-dump/dump` and
`site/job/db1.example.net/template/db-dump/config` in the playbook
directory.

## Policy: `job.<name>`

| Key | Meaning |
| --- | --- |
| `script` | file name of the program (required) |
| `timer.calendar` | `OnCalendar=` of the timer (required); checked with `systemd-analyze calendar` |
| `timer.persistent` | `Persistent=`: run once after boot when a run was missed |
| `timer.delay` | `RandomizedDelaySec=` |
| `timeout` | `TimeoutStartSec=` of the service; without it a run has no limit |
| `user` | the user the program runs as; `root` without it |
| `packages` | packages the job needs, in the syntax of `package.packages` |
| `env` | map of environment variables of the program |
| `config` | list of file names: templates rendered for the program |

A job name matches `[A-Za-z0-9][A-Za-z0-9_.-]*`; `script` and the names
of `config` are plain file names. The user of a job is declared under
`user:` of the policy; the role only checks that it exists.

### Where the files come from

The first that exists is used; none is an error that lists the three:

| | `script` | a name of `config` |
| --- | --- | --- |
| 1 | `site/job/<hostname>/file/<job>/<script>` | `site/job/<hostname>/template/<job>/<name>` |
| 2 | `site/job/common/file/<job>/<script>` | `site/job/common/template/<job>/<name>` |
| 3 | `site/job/common/file/<script>` | `site/job/common/template/<name>` |

The run prints the path it took. A template is rendered like a template
of a kit: it sees the whole policy (`host`), the secrets (`confidential`)
and its own job as `job` (`job.name`, `job.env`, ...).

### `env`

A value is a string, a number, a boolean (`true`, `false`) or a list of
them. A list becomes one variable, its items joined with a tab. The
variables reach the program through `EnvironmentFile=` of the service, so
the program may be written in anything. `JOB_NAME` and `JOB_CONFIG` are
set by the unit and refused in `env`.

## What the role manages

| What | Where |
| --- | --- |
| the program | `/opt/host-policy/job/<name>`, root:root 0755 |
| directory of the job | `/etc/site/job/<name>/`, root:<group of the user> 0750 |
| `env` | `/etc/site/job/<name>/env`, root:root 0600, read by systemd |
| a file of `config` | `/etc/site/job/<name>/<file>`, owned by the user of the job, 0600 |
| units | `/etc/systemd/system/host-policy-job-<name>.service` and `.timer` |

The program gets `JOB_NAME` and `JOB_CONFIG`, the directory of the job, in
its environment, next to the variables of `env`.

```sh
systemctl list-timers 'host-policy-job-*'
systemctl start host-policy-job-<name>.service      # a run outside the schedule
journalctl -u host-policy-job-<name>.service
```

## Behaviour

- **Exclusive.** `/opt/host-policy/job`, `/etc/site/job`, every directory
  of a job and the units named `host-policy-job-*` hold only what the
  policy lists. The timer of a job taken off the policy is stopped and
  disabled, then its files are removed. A run in progress is left to end.
- **One run at a time.** The service is `Type=oneshot`: a timer that
  elapses while the job runs starts no second run. When the run ends and
  the schedule has passed in the meantime, one more run starts at once.
  Two different jobs may run at the same time.
- **A changed unit restarts the timer,** never the service. A changed
  program, `env` or configuration file counts from the next run.
- **No content in the output.** `env` and the files of `config` may hold
  secrets, so `--diff` does not show them.
- **Packages** are installed by this role, at the end of the run. A job
  taken off the policy leaves its packages installed.
