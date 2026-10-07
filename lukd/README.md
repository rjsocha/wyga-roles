# wyga/lukd

Installs and configures lukd, the server of luk - SSH-Authenticated Storage
Server, from the host policy. Everything the service needs is declared
under `setup.lukd`; secrets come from `confidential.lukd`.

- Activates on `setup.lukd`. `setup.lukd.skip: true` turns the role off.
- `wyga/host-policy` runs it after `wyga/user-manager`, so users declared
  in the policy exist by then.
- Alone: the playbook `lukd-config` (`load-policy`, `load-confidential`,
  `wyga/lukd`).
- The client side is `wyga/luk`.

Written against lukd 0.1.10. The configuration reference below is a summary;
the authority is `lukd check` and the annotated example the package ships
in `/usr/share/doc/lukd/examples/config.yaml`.

## Quick start

A backup intake for every host whose certificate the CA `hosts` signed:

```yaml
policy:
- hostname: backup.example.net
  setup:
    lukd:
      ca:
        host: [hosts]
      path:
        - /storage
      config:
        root: /var/lib/luk
        listen:
          intake:
            addr: 0.0.0.0:8443
            host: [backup.example.net]
            tls:
              mode: self
              cert: tls/intake.crt
              key: tls/intake.key
              host: backup.example.net
        endpoint:
          backup:
            listen: intake
            endpoint: /backup
            path: queue/backup
            allow: ["hosts:*"]
            respond: accept
        pipeline:
          archive:
            endpoint: [backup]
            steps:
              - store: archive
        storage:
          archive:
            type: local
            base: /storage/archive
            path: !unsafe "{{ .Origin }}/{{ .Year }}/{{ .Month }}/{{ .Day }}/{{ .File }}"
```

## What the role manages

| Policy key | Result on the host |
| --- | --- |
| `config` | `/etc/site/lukd/config.yaml`, root:luk 0640 |
| `identity` | `/etc/site/lukd/ssh.d/<name>.pub`, root:luk 0640 |
| `ca.host`, `ca.user` | `/etc/site/lukd/ssh.d/ca/{host,user}/<name>.pub` |
| `gpg` | `/etc/site/lukd/gpg.d/<file>` |
| `script` | `/opt/luk/<name>`, root:root 0755 |
| `package` | extra deb packages, installed with `lukd` |
| `run` | `/etc/site/lukd/run.d/<job>.yaml`, root:root 0644 |
| `path` | the directory, luk:luk 0750; `ReadWritePaths=` drop-ins of both roles |
| `docker` | `SupplementaryGroups=docker` drop-in of the process role |
| `confidential.lukd.credential` | `/etc/site/lukd/credentials.d/<name>`, root:root 0600 |
| `confidential.lukd.encrypt.password` | `/etc/site/lukd/password.d/<name>`, root:luk 0640 |
| `confidential.lukd.auth.basic` | user sets; an expose names one with `auth.basic: <set>` and gets its users in `config.yaml` |
| `confidential.lukd.config` | merged over `config` |

Units: `lukd.service` (enabled; it groups `lukd-receive.service` and
`lukd-process.service` and pulls in `lukd-run.socket`, which every `run`
and `relay` step needs). The role touches no other unit. The package
needs systemd 257 or newer.

The unit of the process role hides the TLS, ACME and nonce directories at
their default places below `/var/lib/luk` and `/run/luk`. A configuration
that moves `root`, the `tls` files or `auth.nonces` needs a drop-in of its
own for `lukd-process.service`; the role does not write one.

## Policy: `setup.lukd`

### `config` (required)

The lukd configuration tree, written to `config.yaml` as it stands in the
policy. See "lukd configuration" below.

lukd path templates use `{{ }}` as Ansible does. Mark every such value
`!unsafe`, or Ansible tries to render it:

```yaml
path: !unsafe "{{ .Sender }}/{{ .File }}"
```

### `identity`

List of names. Each `key/user/<name>` of the policy repository (one SSH
public key per line) becomes the identity `<name>`. Use the name in `allow`
and in the capability lists.

```yaml
identity:
  - robert.socha
```

### `ca`

Lists of CA names for host and user certificates. Each
`key/ca/host/<name>` or `key/ca/user/<name>` (one CA public key per line;
several lines during a rotation) becomes the CA `<name>`. When `<name>` is
a directory, as in the layout of `wyga/ssh-host-certificate`, the role
takes `<name>/host-ca.pub` or `<name>/user-ca.pub`. A certificate of
that CA is the identity `<name>:<Key ID>`.

```yaml
ca:
  host: [hosts]
  user: []
```

### `gpg`

List of file names in `key/gpg/` holding OpenPGP public keys, for the
`key` recipients of `encrypt` steps. A name ending in `.asc`, `.gpg`,
`.pgp` or `.key` is copied as it is; any other name gets `.asc`.

```yaml
gpg:
  - robert@example.net        # -> gpg.d/robert@example.net.asc
  - team.asc                  # -> gpg.d/team.asc
```

### `script`

List of file names in `site/luk/` of the policy repository, copied to
`/opt/luk/`. For programs of `run` steps and jobs that belong to one site.
Programs shared between sites belong in a package (`package`).

### `package`

List of extra packages installed together with `lukd`, in the syntax of
`wyga/install-packages`.

### `run`

Jobs of `lukd run`: programs a pipeline starts as another user through the
root helper (`relay: <job>` step, or `luk-job run` inside a `run` step).
The map key is the job name (`[a-z0-9][a-z0-9._-]*`).

```yaml
run:
  s3-upload:
    command: /opt/luk/s3-upload   # required, absolute; gets the work directory as its argument
    user: luk-s3                  # optional; must exist (declare it under user: in the policy)
    group: luk-s3                 # optional, needs user: replaces the primary group
    groups: [backup]              # optional supplementary groups
    credentials: [s3]             # names of confidential.lukd.credential
    timeout: 2h                   # default 1h
    state: locked                 # optional: locked or shared; a state directory per job and pipeline
    env:
      BUCKET: example-backup
```

Without `user` the job runs as a systemd dynamic user, one per job and
pipeline. The job reads its credentials from
`$CREDENTIALS_DIRECTORY/<name>`. lukd sets the step environment (`LUK_WORK`,
`LUK_IN`, `LUK_OUT`, `LUK_META`, `LUK_ROOT`, `LUK_ID`, `LUK_PIPELINE`,
`LUK_STEP`, `LUK_SENDER`, `LUK_ENDPOINT`, `LUK_TAGS`, `LUK_NAME`, `LUK_FILE`,
`LUK_HOSTNAME`, `LUK_ORIGIN`) plus `LUK_JOB`, `LUK_TMP` and `LUK_STATE`;
`LUK_*` names are reserved in `env`.

Which pipelines may run a job comes from the lukd configuration, not from
the job: a pipeline with a `relay: <job>` step, or a pipeline whose `run`
step lists the job in `jobs:` (the jobs its program starts with
`luk-job run --job`):

```yaml
setup:
  lukd:
    config:
      pipeline:
        backup:
          steps:
            - run: /opt/luk/backup-flow
              jobs: [dump-db, rustic]
            - relay: s3-upload
```

A job no pipeline names never runs (`lukd check` warns about it).

### `path`

List of absolute directories outside `/var/lib/luk` that lukd writes to: a
storage base on another volume, or a place a `run` program writes. The
role creates each one for `luk` and grants it to both lukd roles. A change
restarts lukd.

### `docker`

`true` lets the programs of `run` steps use the docker socket: the process
role gets the group `docker`. The host must have docker installed. Members
of that group are root on the host in effect; the receive role does not get
it. A change restarts lukd.

### `bcrypt`

Cost of the `auth.basic` hashes, 4 to 31. Default 10.

## Confidential: `confidential.lukd`

```yaml
confidential:
  lukd:
    auth:
      basic:                 # user sets, plain passwords
        developers:          # named by expose.<name>.auth.basic: developers
          dev: "plain password"
    credential:              # files for the jobs of run
      s3: |
        [default]
        aws_access_key_id = ...
    encrypt:
      password:              # passwords of encrypt.insecure, by name
        receiver-a: "long random password"
    config:                  # any part of the lukd configuration, merged over setup.lukd.config
      listen:
        web:
          tls:
            eab: { kid: "KEY_ID", key: "..." }
```

- `auth.basic`: user sets. An expose of the policy names one with
  `auth.basic: <set>`, so the policy shows that basic authentication is
  on and with which users, and the vault holds the passwords. Several
  exposes may name one set. The role hashes each password with bcrypt and
  puts the entries in place of the name. A set named by an expose and
  missing here, or a set here that no expose names, fail the role. The
  salt is derived from the host name, the set and the user, so a hash
  changes only when its password does. The hash is made by crypt(3)
  of the system libcrypt on the controller (no Python package needed);
  without a libcrypt that knows bcrypt the Python module `bcrypt` is used.
- `credential`: every name a job lists in `credentials` must be present
  here; the role refuses the policy otherwise.
- `encrypt.password`: the passwords an `encrypt` step names under `insecure`
  (`symmetric`, `openssl.key`). The file holds the password and one newline;
  trailing newlines of the value are dropped, so a block scalar works. Only
  the process role of lukd reads them. A password the configuration names
  and this map lacks fails the validation of `config.yaml`. lukd reads a
  password when the step runs, so a changed one needs no reload.
- `config`: merged recursively; use it for the few secret values that live
  inside the lukd configuration.

## Behaviour

- **Exclusive directories.** `ssh.d`, `ssh.d/ca/host`, `ssh.d/ca/user`,
  `gpg.d`, `run.d`, `credentials.d` and `password.d` hold only what the policy lists; any
  other file there is removed. Taking a name off the policy takes its
  access away. `/opt/luk` is not cleaned, packages install there too.
- **Validation before activation.** `config.yaml` is checked with
  `lukd check --no-running` next to the live file before it replaces it.
  An invalid configuration fails the task and changes nothing.
- **Reload, restart on need.** A change reloads each lukd role; a role
  whose reload is refused (a restart-only setting: `root`, `listen`,
  `limits.conn`, `limits.header.timeout`, `auth.nonces`) or that is not
  running is restarted. A change of `path` restarts lukd.
- **Self-signed certificates.** With a `tls.mode: self` listener the role
  runs `lukd tls generate` as `luk`. Existing certificates are kept. Read
  the pins with `lukd tls pin`.
- **Upgrades.** A new lukd may refuse a configuration the old one took.
  The package restarts lukd before the role writes the new file, so the
  service is down until the same run reaches the configuration. Change
  the policy to the new syntax before the run that upgrades.

## lukd configuration (`config`)

### Identities and the `allow` syntax

An identity is a plain key (`identity`, or `auth.keys` in the config) or a
certificate of a CA (`ca`), named `<ca>:<Key ID>`. Lists of identities
appear in `endpoint.<n>.allow`, in every capability list and in
`expose.<n>.auth.ssh.allow`:

| Entry | Matches |
| --- | --- |
| `robert.socha` | the plain key of that name |
| `hosts:*` | every certificate of the CA `hosts` |
| `hosts:*.example.net` | a certificate with a principal matching the glob |
| `hosts#db*.example.net` | a certificate whose Key ID matches the glob |
| `*` | every identity lukd knows |

A capability list that is absent or `[]` grants the capability to no one.
`true` and `false` in place of a list fail `lukd check`.

RSA keys shorter than 2048 bits and DSA keys are refused, as are `ssh-rsa`
(SHA-1) signatures.

### Top level

| Key | Meaning |
| --- | --- |
| `root` | state directory; relative paths below resolve against it. `/var/lib/luk` |
| `log.level` | `debug`, `info`, `warn`, `error` |
| `limits.conn.max`, `limits.conn.idle` | connections per address (1024), idle time (60s) |
| `limits.header.timeout` | time to send the request headers (10s) |
| `limits.queue.reserve` | free space kept on the queue volume (1G) |
| `limits.failed.age` | lifetime of failed queue entries (3d) |
| `auth.clock_skew` | allowed clock difference of a signed request (1m, at most 1h) |
| `auth.nonces` | nonce cache directory (`/run/luk/nonces`) |
| `gpg.keys` | directory of `key` recipients (`/etc/site/lukd/gpg.d`) |
| `gpg.wkd.cache` | lifetime of cached WKD keys (1d) |

Keys and CAs normally come from `identity` and `ca` of the role. A CA
revocation list still lives in the config:

```yaml
auth:
  ca:
    - name: hosts          # no key: the key is in ssh.d/ca/host/hosts.pub
      revoked:
        key_ids: [old.example.net]
        serials: [42]
```

### `listen.<name>`

| Key | Meaning |
| --- | --- |
| `addr` | `ip:port`; several listeners may share an address |
| `host` | list of names routed to this listener (Host header, SNI) |
| `public` | base URL of answers; needed behind a reverse proxy |
| `acme` | `true` on a plain listener: answers HTTP-01 and redirects to https |
| `tls.mode` | `self`, `files` or `acme` |
| `tls.cert`, `tls.key` | certificate and key (`self`, `files`) |
| `tls.host` | name in the self-signed certificate |
| `tls.algorithm` | `ed25519` (default) or `ecdsa-p256`, mode `self` |
| `tls.email`, `tls.directory`, `tls.eab` | ACME account, directory URL, external account binding |

Without `tls` the listener is plain HTTP, for use behind a proxy that
terminates TLS. Clients of a `self` or `files` listener pin its
certificate (`lukd tls pin`); clients of an `acme` listener or of a proxy
with a public certificate need no pin.

### `endpoint.<name>`

| Key | Meaning |
| --- | --- |
| `listen` | listener name or list of names |
| `endpoint` | URL path of the endpoint, unique per listener |
| `path` | queue directory; endpoint paths must not nest |
| `allow` | who may upload |
| `respond` | `accept` (answer once queued) or `url` (answer with the link) |
| `storage` | the storage of the link, with `respond: url` |
| `limits.body.size`, `.idle`, `.timeout` | largest upload, idle time, total time |

Capabilities, each a list of identities granted on top of `allow`:

| Key | Grants |
| --- | --- |
| `link.remove` | `luk link --rm` |
| `link.ttl` | `luk link --ttl` (the storage needs `ttl.user`) |
| `link.replace` | `luk send --mutable` and `luk link --file`; pipelines of the endpoint must be store steps only |
| `link.list` | `luk link ls` |
| `pretty.allow` | `luk send --pretty-url`; `pretty.bits` 64 to 128 |
| `private.owner` | `luk send --private` (the storage needs `protect`) |
| `private.any` | `luk send --private --any` |
| `secret.allow` | `luk send --secret`, kept in RAM; needs `secret.path` and `secret.storage` |
| `backup.hostname.any` | may send any `--backup` hostname |
| `backup.hostname.principal` | may send only a principal of its own certificate as the hostname |

Without the `backup.hostname` block every admitted identity may send any
hostname. With it, an identity on neither list is refused `--backup` with
403, before the body. On such an endpoint `.Origin` in a storage path can
be trusted.

`pretty` and `secret` need their `allow`; a `--secret` upload of an
identity outside `secret.allow` is answered 422.

Quota, a token bucket per identity:

```yaml
quota:
  mode: enforce            # or passive: account and log, never refuse
  rate: 10G/1d
  burst: 50G               # largest single upload; default the size of rate
  class:
    - name: large
      members: ["hosts#db*.example.net"]
      rate: 50G/1d
      burst: 100G
```

### `pipeline.<name>`

A pipeline runs for an upload when the upload's endpoint is in `endpoint`
and the upload carries every tag in `tags`. All matching pipelines run,
unless one has `claim: true`: then it runs alone. A pipeline name matches
`[A-Za-z0-9_][A-Za-z0-9_.-]*`.

| Key | Meaning |
| --- | --- |
| `endpoint` | list of endpoint names (required) |
| `tags` | tags the upload must carry; none matches every upload |
| `claim` | the only pipeline of a matching upload; needs `tags` |
| `timeout` | limit of one run |
| `queue.group`, `queue.order` | pipelines of one upload in a group run in order |
| `queue.concurrency` | runs of this pipeline at once (1) |
| `steps` | list of steps, run in order |

Steps:

| Step | Meaning |
| --- | --- |
| `store: <storage>` or a list | store the current files |
| `run: /path` | run a program as `luk` on the files; `env:` adds variables; `tee: true` keeps the input for the next step; `jobs: [<job>, ...]` lists the jobs of `run` (role key) the program may start with `luk-job run --job`, none without it |
| `relay: <job>` | run a job of `run` (role key) on the files as its user; the next step gets the same files |
| `encrypt:` | OpenPGP-encrypt for `wkd:` and `key:` recipients; `strict: true` fails on any unusable recipient; `insecure:` adds passwords (below) |

`encrypt.insecure` is for receivers without an OpenPGP key. The passwords
come from `confidential.lukd.encrypt.password`:

```yaml
- encrypt:
    key: [backup@example.net]
    insecure:
      symmetric: [receiver-a]        # these passwords also decrypt the .gpg files
      openssl:
        key: receiver-a              # one password
        files: ["*.plain.sql.zst"]   # globs on the file name as it enters the step
```

A file that matches `openssl.files` is written only as `<name>.enc`, in the
format of `openssl enc -aes-256-cbc -pbkdf2`, and gets no `.gpg`; the
format has no integrity check. To publish a file both ways, let the `run`
step before it put the file into the set under two names.

### `storage.<name>`

| Key | Meaning |
| --- | --- |
| `type` | `local` |
| `base` | directory; relative to `root`, or absolute (then list it in `path` of the role) |
| `path` | name template of a stored file |
| `expose` | expose that serves the public files |
| `protect` | expose with `auth.ssh` that serves the private files |
| `conflict` | `version` (default), `reject` or `replace` when the name exists |
| `dedup` | with `version`: keep the newest instead of an identical copy (true) |
| `hardlink` | one copy per content (true) |
| `links.max` | most names with one content per identity (100) |
| `shard` | 0 to 4 levels of hash directories; not with an `index` expose |
| `catalog` | keep `<base>/.db/catalog.json` |
| `ttl.user`, `ttl.min`, `ttl.max` | whether the client ttl counts, and its bounds; `max` alone is a fixed lifetime |
| `cleanup.age` | remove files without an expiry after that age |
| `retention` | rules that keep a number of files per series and prune the rest (below) |
| `watch` | thresholds that report a series as late, too small, too large or unchanged (below) |
| `random.alphabet`, `random.length` | characters and length of `.Random` |

Variables of `path`: `.Sender`, `.Endpoint`, `.Year`, `.Month`, `.Day`,
`.Hour`, `.Minute`, `.Seconds`, `.Id`, `.Random`, `.File`, `.Tags`,
`.Hostname` (the `--backup` hostname) and `.Origin` (`.Hostname` when set,
else `.Sender`). The time variables are UTC; there is no `.Date`.

Retention thins backups per series, grandfather-father-son:

```yaml
retention:
  - origin: ["db1-prod", "*-prod"]     # globs on the origin; first matching rule wins
    keep: {last: 3, daily: 14, weekly: 8, monthly: 12, within: 2d}
  - origin: ["*-stage"]
    keep: {daily: 7}
  - keep: {daily: 7, weekly: 4}        # no origin: every other origin; must be last
```

- A series is one pipeline, origin and file name. The origin is the
  `--backup` hostname, else the sender.
- `last: N` keeps the N newest files; `daily`, `weekly`, `monthly` and
  `yearly` keep the newest file of each of the last N days, ISO weeks,
  months and years that have a file. `within: 2d` keeps every file of
  the last two days, so a burst of uploads cannot push the older copies
  out. The kept set is the union.
- A series no rule matches is never pruned. Retention counts files, not
  age: when a host stops sending, its last copies stay.
- It works next to `ttl` and `cleanup.age`; a file goes when any of them
  removes it.
- A file name that carries the date (`db-20261004.sql.gz`) is a series of
  its own every day, so retention never prunes it. Send a constant name
  and put the date in `path`, or bound such files with `ttl`.
- `retention` together with `conflict: replace` fails `lukd check`.
- `lukd storage retention --storage <name>` prints the plan (KEEP with the
  reason, or PRUNE) without removing anything.

Watch reports a series that breaks a threshold. Only the thresholds written
here count; nothing is learned from history:

```yaml
watch:
  - origin: ["db1-prod"]               # globs on the origin
    file: ["db.sql*"]                  # globs on the file name
    every: 26h                         # a newer file is expected within this time
    size: {min: 2G, max: 20G, step: 500M}   # bounds, and the largest change between two files
    same: 3                            # this many identical files in a row is a problem
```

- The result is in `status.json`, which is the object
  `{"pipelines": [...], "watch": [...]}` (older versions wrote a plain list).
- The Checkmk check of the package, `contrib/checkmk/luk_status`, turns
  each watched series into a service `luk watch <storage> <pipeline>
  <origin>/<file>`. Replace the deployed check when lukd is upgraded: an
  older check does not read the new `status.json`. The role does not
  install the check.
- `lukd storage watch --storage <name> --suggest` proposes thresholds from
  the files stored so far.

### `expose.<name>`

| Key | Meaning |
| --- | --- |
| `listen` | listener name or list of names |
| `path` | URL prefix; the longest matching prefix wins |
| `auth.basic` | name of a user set of `confidential.lukd.auth.basic` |
| `auth.ssh.allow` | signed `luk get` only; who downloads `--private --any` files, or every file when it is the `expose` of a storage |
| `plain` | no authentication on purpose; silences the warnings |
| `index` | HTML listing of directory URLs; not with `auth.ssh`; on a sharded storage it fails `lukd check` |

An `auth.ssh` expose has two uses. As the `protect` of a storage it serves
the private files (`luk send --private`). As the `expose` of a storage it
serves every file of that storage, to the identities of `allow` and to
signed requests only; its listener needs a public `https` URL.

## Recipes

Uploads behind a reverse proxy that terminates TLS:

```yaml
listen:
  ingest:
    addr: "10.0.0.5:80"
    host: [endpoint.drop.example.net]
    public: https://endpoint.drop.example.net
```

Hosts send backups only under their own name, an operator under any:

```yaml
endpoint:
  backup:
    allow: [robert.socha, "hosts:*"]
    backup:
      hostname:
        any: [robert.socha]
        principal: ["hosts:*"]
```

A drop endpoint where only one identity manages its links:

```yaml
endpoint:
  drop:
    allow: ["*"]
    respond: url
    storage: drop
    link:
      remove: [robert.socha]
      ttl: [robert.socha]
      replace: [robert.socha]
      list: [robert.socha]
```

Backups readable by one restore host, and by nobody over plain HTTP:

```yaml
expose:
  archive:
    listen: intake
    path: /a/
    auth:
      ssh:
        allow: ["hosts#restore.example.net"]
storage:
  archive:
    type: local
    base: /storage/archive
    expose: archive
```

```sh
luk get luk://backup.example.net:8443/a/db1-prod/              # listing (--json, -r)
luk get luk://backup.example.net:8443/a/db1-prod/ -o restore/  # the directory; identical files are skipped
```

## On the host

```sh
lukd check                     # validate the configuration
lukd status                    # last result per pipeline and sender
lukd queue ls                  # failed entries
lukd queue retry --id <id>     # run a failed entry again
lukd queue rm --id <id>
lukd tls pin                   # pins of the self and files listeners
lukd quota ls                  # buckets per endpoint and identity
lukd storage ls                # stored files
lukd storage retention --storage <name>   # retention plan, removes nothing
lukd storage watch --storage <name> --suggest   # thresholds proposed from the stored files
journalctl -u 'lukd*' -f       # both roles and the job units
```
