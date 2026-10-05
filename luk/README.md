# wyga/luk

Installs the client of luk - SSH-Authenticated Storage Server and writes its
system-wide configuration, `/etc/site/luk/config.yaml`, from the host
policy. luk uploads files to a lukd endpoint; every request is signed with
an SSH key, so the server decides by who signed it.

- Activates on `setup.luk`. `setup.luk.skip: true` turns the role off.
- `wyga/host-policy` runs it after `wyga/lukd`.
- Alone: the playbook `luk-config` (`load-policy`, `wyga/luk`).
- The server side is `wyga/lukd`.

Written against luk 0.2.0.

## Quick start

A host that sends backups as itself, signed with its SSH host key:

```yaml
policy:
- hostname: db1.example.net
  setup:
    luk:
      key: host
      default: backup
      endpoint:
        backup: https://backup.example.net:8443/backup#lusab-babad-gutih-tugad-hajop-kizof
```

On the host, as root:

```sh
luk send --backup --file /var/backups/db.sql.gz
```

## Policy: `setup.luk`

| Key | Meaning |
| --- | --- |
| `key` | signing key of every endpoint without its own: `host`, an absolute path, `~/...` or `SHA256:...` |
| `default` | endpoint used without `--endpoint`; must be one of `endpoint` |
| `endpoint.<name>` | the URL of the lukd endpoint, with the pins in its fragment; or a map (below) |
| `endpoint.<name>.url` | URL of the lukd endpoint (required); may carry the pins in its fragment |
| `endpoint.<name>.pin` | pins of the lukd key: one, or a list; joined with those of the URL |
| `endpoint.<name>.key` | signing key of this endpoint, same forms as `key` |
| `link` | map of a link host to the endpoint `luk link` uses for its URLs |
| `alias` | map of a command name to its arguments |
| `skip` | `true` turns the role off |

Everything except `key: host` and the endpoint shorthand is written to the
configuration as it stands: an endpoint given as a URL becomes `url`, and
the fragment of a URL becomes `pin`, a list.

### `key`

| Value | luk signs with |
| --- | --- |
| `host` | the SSH host key of the machine (see below) |
| `/path/to/key` | that private key file; `<path>-cert.pub` next to it is used as its certificate |
| `/path/to/key.pub` | the key of that public file, held by the SSH agent |
| `SHA256:...` | the agent key with that fingerprint |
| absent | the first key of the SSH agent |

`key: host` selects the first present of `/etc/ssh/ssh_host_ed25519_key`,
`ssh_host_rsa_key` and `ssh_host_ecdsa_key` and writes its path. An
OpenSSH host certificate is named `<key>-cert.pub`, so on a host with
`setup.ssh.host.certificate` luk signs as the host certificate, and lukd
admits it through the CA (`<ca>:<hostname>`). No key is distributed.

The host key is readable by root only: a configuration with `key: host`
serves root.

### `pin`

The pin is the identity key of lukd: luk talks to an endpoint only through
a channel with the server that holds that key, whatever TLS is in between.
Without a pin luk refuses the endpoint. Read it on the server with
`lukd key`, which prints the key (43 characters) and its six-word form
(`lusab-babad-gutih-tugad-hajop-kizof`); both are pins. Several pins (a
list, or comma-separated in the fragment) let a key be rotated: the server
is accepted when its key matches any of them.

```yaml
endpoint:
  backup: https://backup.example.net:8443/backup#lusab-babad-gutih-tugad-hajop-kizof
  drop:
    url: https://backup.example.net:8443/drop#lusab-babad-gutih-tugad-hajop-kizof
    key: /etc/site/luk/drop.key
```

The TLS pin of older versions (`sha256//...`) is not a pin of lukd; luk
refuses it with `an endpoint pin is the lukd key: run luk scan URL`.

### `link` and `alias`

```yaml
link:
  drop.example.net: drop      # luk link https://drop.example.net/... uses endpoint drop
alias:
  nightly: [send, --endpoint, backup, --tag, nightly, --ttl, 7d]
```

## Behaviour

- The file is `/etc/site/luk/config.yaml`, root:root 0644. It is checked
  with `luk config check` before it replaces the current one; an invalid
  configuration fails the task and changes nothing.
- It is the global layer. A user's `~/.config/luk/config.yaml` overrides
  it: `default` and `key` replace, endpoints and aliases merge by name,
  link mappings by host. A user endpoint with a `url` replaces the global
  one of its name; one without a `url` sets only the key of the global
  one (`luk config endpoint key`).

## Using luk on the host

```sh
luk send --file FILE                 # to the default endpoint
luk send -e backup --backup --file FILE --tag prod --ttl 7d
some-command | luk send --stdin --name dump.sql
luk scan --endpoints URL             # endpoints the key may use, with their flags
luk config show                      # effective configuration and its sources
luk config check
```

Options of `luk send` worth knowing in a policy context:

| Option | Meaning |
| --- | --- |
| `--backup` | adds the hostname, absolute path and mtime; the endpoint may tie the hostname to the certificate (`backup.hostname`) |
| `--tag` | tags select the pipelines on the server; repeatable |
| `--ttl` | lifetime, or `max`; the storage decides whether it counts |
| `--dry-run` | every server check, no body, nothing stored |
| `--bwlimit` | upload rate limit |
| `--quiet` | print only the URL; nothing on a `respond: accept` endpoint |
| `--json` | print the server answer |

Links, secrets and private files (`--mutable`, `--secret`, `--private`,
`luk link`, `luk get`) need the matching capability on the endpoint; see
`wyga/lukd`.

`luk get` downloads with a signed request. A URL that ends with a slash
names a directory of an expose that serves a whole storage to signed
requests (`auth.ssh` as the `expose` of a storage):

```sh
luk get luk://backup.example.net/a/db1-prod/               # listing; -r recursive, --json
luk get luk://backup.example.net/a/db1-prod/ -o restore/   # every file below; identical files are skipped
luk get luk://backup.example.net/a/db1-prod/db.sql.gz.gpg -c | gpg -d | zcat   # one file to stdout
```

Exit codes of `luk send`: 0 ok, 1 usage or configuration, 2 rejected by
the server, 3 transfer or server error, 4 hash mismatch, 130 interrupted.
