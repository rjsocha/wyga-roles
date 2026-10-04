# wyga/luk

Configures the luk client from the host policy: the package and the
system-wide configuration `/etc/site/luk/config.yaml`. The role activates on
`setup.luk`; `setup.luk.skip: true` turns it off.

`wyga/host-policy` runs it after `wyga/lukd`. Alone: the playbook
`luk-config` (`load-policy`, `wyga/luk`).

## Policy

```yaml
policy:
- hostname: db1.example.net
  setup:
    luk:
      key: host              # host, an absolute path, ~/..., or SHA256:...
      default: backup
      endpoint:
        backup:
          url: https://backup.example.net:8443/backup
          pin: sha256//...   # self-signed servers only
          key: host          # optional, overrides the key above
      link:
        get.example.net: backup
      alias:
        nightly: [send, --endpoint, backup, --tag, nightly]
```

Everything but `key: host` is the luk configuration as it is.

`key: host` selects the SSH host key of the machine, the first present of
`/etc/ssh/ssh_host_ed25519_key`, `ssh_host_rsa_key`, `ssh_host_ecdsa_key`.
luk uses `<key>-cert.pub` next to it as the certificate, which is the name of
an OpenSSH host certificate: with `ssh.host.certificate` in the policy the
host signs as its certificate, and lukd admits it through `ca.host`. The host
key is readable by root only, so this configuration serves root.

The file is checked with `luk config check` before it replaces the current
one.
