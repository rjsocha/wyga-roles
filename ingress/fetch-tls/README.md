# ingress/fetch-tls

Configures the `site-fetch-tls` client on a host: renders its config, writes the
password secrets from the vault, ensures the package is installed, and triggers
a fetch on change.

The engine itself (the `site-fetch-tls` binary, systemd service and timer) is
shipped by the **`site-fetch-tls`** Debian package. This role only provides the
per-host configuration; it installs the package automatically when missing.

The engine pulls per-domain certificate bundles (`<zone>.tar.gz`) over HTTP from
a distribution host, verifies certificate/key, installs the combined PEM into
the storage directory with the requested owner/mode, mirrors aliases, and runs a
reload command when anything changed. Missing domains get a short-lived
self-signed fallback.

Activated when `setup.ingress.tls.fetch` is defined in the host policy.

---

## What it produces on the host

| Path | Purpose |
|------|---------|
| `/etc/site/tls/fetch/config` | Rendered engine config (`0400 root:root`) |
| `/etc/site/tls/fetch/secret` | Default password file (only if a default password is set in the vault) |
| `/etc/site/tls/fetch/secret.<zone>` | Per-zone password file (only for zones with their own vault password) |
| `<storage>` | Certificate storage directory, e.g. `/var/site/tls` |

---

## Policy

The policy holds **structure only** — no passwords. Top-level keys are the
defaults; each `domain` entry may override them per zone.

```yaml
setup:
  ingress:
    tls:
      fetch:
        host: http://certs.example.net        # full URL incl. scheme
        storage: /var/site/tls                # default: /var/site/tls
        owner: root                           # default: root
        group: root                           # default: root
        mode: "0400"                          # default: 0400
        reload: "systemctl reload nginx"      # optional, run once on change
        domain:
          - zone: app.example.com
            alias:
              - admin.app.example.com
              - status.app.example.com
          - zone: shop.example.com
```

### Defaults

`host` is the only required default. `storage`, `owner`, `group`, `mode` fall
back to the values above when omitted. `reload` is optional — without it nothing
is run after an update.

`host` is taken verbatim, including the scheme — set `http://…` or `https://…`
explicitly. There is no automatic prefixing.

### Per-domain overrides

Any default can be overridden inside a `domain` entry. Only `zone` is required.

```yaml
        domain:
          - zone: other.example.com
            host: https://certs-eu.example.net    # different source
            storage: /var/lib/other/tls           # different storage dir
            owner: www-data
            group: www-data
            mode: "0440"
            reload: "systemctl reload apache2"     # zone-specific reload
            alias:
              - www.other.example.com
```

`alias` zones receive a copy of the zone's PEM and are refreshed whenever the
source zone changes.

---

## Confidential (ansible-vault)

All password material lives in the vault, mirroring the policy path. `PASSWORD`
in the engine is a **path to a file** containing the private-key passphrase;
this role writes those files for you.

```yaml
confidential:
  setup:
    ingress:
      tls:
        fetch:
          password: "the-default-key-passphrase"   # default for every zone
          domain:
            shop.example.com: NONE                  # this zone ships an unencrypted key
            other.example.com: "zone-specific-pass" # this zone uses its own passphrase
```

### Resolution rules

- **Default** — `fetch.password` set → written to `/etc/site/tls/fetch/secret`,
  used for every zone that has no own entry. Omitted → the default becomes
  `NONE` (keys are expected unencrypted).
- **Per-zone** — an entry under `fetch.domain.<zone>`:
  - value `NONE` → that zone's key is treated as unencrypted (no decryption).
  - any other value → written to `/etc/site/tls/fetch/secret.<zone>` and used
    only for that zone.
- **Zone not listed** under `fetch.domain` → inherits the default password.

A zone whose key is encrypted with the default passphrase needs **no** entry in
the vault — it inherits the default automatically. List a zone only to give it
its own passphrase or to mark it `NONE`.

---

## Full example

A host fronting `nginx`, fetching three certs from one distribution host. Two
zones use the default passphrase, `shop.example.com` ships an unencrypted key.

**policy**

```yaml
setup:
  ingress:
    tls:
      fetch:
        host: http://certs.example.net
        storage: /var/site/tls
        reload: "systemctl reload nginx"
        domain:
          - zone: app.example.com
            alias:
              - admin.app.example.com
              - status.app.example.com
          - zone: api.example.com
          - zone: shop.example.com
```

**confidential (vault)**

```yaml
confidential:
  setup:
    ingress:
      tls:
        fetch:
          password: "shared-passphrase"
          domain:
            shop.example.com: NONE
```

Result: `app.example.com` and `api.example.com` decrypt with the shared
passphrase, `shop.example.com` is taken as-is, and `systemctl reload nginx` runs
once if any certificate changed.
