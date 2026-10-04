# wyga/lukd

Configures lukd from the host policy: the package, the configuration, the
identities, the pipeline programs and the jobs of `lukd run`. The role
activates on `setup.lukd`; `setup.lukd.skip: true` turns it off.

`wyga/host-policy` runs it after `wyga/user-manager`, so the users of the
jobs exist by then. Alone: the playbook `lukd-config` (`load-policy`,
`load-confidential`, `wyga/lukd`).

## Policy

```yaml
policy:
- hostname: backup.example.net
  setup:
    lukd:
      package:               # extra packages, installed with lukd
        - lukd-job-s3
      script:                # site/luk/<name> -> /opt/luk/<name>
        - dbdump
      identity:              # key/user/<name> -> ssh.d/<name>.pub
        - robert.socha
      ca:
        host: [hosts]        # key/ca/host/<name> -> ssh.d/ca/host/<name>.pub
        user: []             # key/ca/user/<name> -> ssh.d/ca/user/<name>.pub
      gpg:                   # key/gpg/<file> -> gpg.d/<file> (.asc added when the
                             # name has no .asc, .gpg, .pgp or .key)
        - robert@example.net
      path:                  # created for luk, ReadWritePaths of both roles
        - /storage
      run:                   # run.d/<job>.yaml; enables lukd-run.socket
        s3-upload:
          user: luk-s3       # must exist: declare it under user: in the policy
          command: /opt/luk/s3-upload
          credentials: [s3]  # names of confidential.lukd.credential
          timeout: 2h
          env:
            BUCKET: example-backup
      bcrypt: 10             # cost of the auth.basic hashes (default 10)
      config:                # the lukd configuration, written as it is
        root: /var/lib/luk
        storage:
          archive:
            type: local
            base: /storage/archive
            path: !unsafe "{{ .Sender }}/{{ .Year }}/{{ .File }}"
```

`config` is the lukd configuration tree, one to one. A path template of
lukd uses `{{ }}` as Ansible does: mark every such value `!unsafe`.

## Confidential

```yaml
confidential:
  lukd:
    basic:                   # expose.<name>.auth.basic, hashed by the role
      publish:
        dev: "plain password"
    credential:              # /etc/site/lukd/credentials/<name>, root 0600
      s3: |
        ...
    config:                  # merged over setup.lukd.config
      listen:
        intake:
          tls:
            eab: { key: "..." }
```

The bcrypt salt of a `basic` entry comes from the host name, the expose and
the user, so a hash changes only with its password. The controller needs the
python module `bcrypt` when `basic` is used.

## Behaviour

- `ssh.d`, `ssh.d/ca/host`, `ssh.d/ca/user`, `gpg.d`, `run.d` and
  `credentials` hold only what the policy lists: other files are removed.
  `/opt/luk` is not cleaned (packages install there too).
- `config.yaml` is checked with `lukd check --no-running` next to the live
  one before it replaces it; an invalid configuration fails the task and
  changes nothing.
- A change reloads lukd; when the reload is refused (a restart-only
  setting) lukd is restarted. A change of `path` restarts it.
