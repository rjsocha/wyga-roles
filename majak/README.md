# wyga/majak

Installs and configures majak - the DLG expose control plane: SNI edge,
API (`majak serve`) and the overlay lighthouse (`majak vpn`). Declared
under `setup.majak`; the overlay CA comes from `confidential.majak.ca`.

## Policy

```yaml
policy:
- hostname: host.dlg.example.net
  setup:
    majak:
      config:                       # /etc/site/majak/config.yaml as is
        ip: {public: 192.0.2.10}
        api:
          host: api.majak.dlg.example.net
          listen: "240.240.255.4:443"
          tls: {cert: /var/lib/majak/api.crt, key: /var/lib/majak/api.key}
        db: {path: /var/lib/majak/majak.db}
        vpn: {cidr: 198.19.0.0/23, ip: 198.19.0.1, port: 4242}
        security:
          identity: {token: "majak@example"}
        binder:
          - name: ci
            key: ["ssh-ed25519 AAAA... ci"]
```

## Confidential

```yaml
confidential:
  majak:
    ca:
      cert: |
        -----BEGIN NEBULA CERTIFICATE V2-----
        ...
      key: |
        -----BEGIN NEBULA ED25519 PRIVATE KEY-----
        ...
```

Generated once, e.g. `nebula-cert ca -name majak -networks 198.19.0.0/23`.

## What the role manages

| Source | Result on the host |
| --- | --- |
| `config` | `/etc/site/majak/config.yaml`, root:majak 0640, merged with `confidential.majak.config`; `vpn.ca` always points at the files below |
| `confidential.majak.ca` | `/etc/site/majak/ca.crt` and `ca.key`, root:majak 0640 |

The API certificate is not managed: `majak serve` generates it on first
start at `api.tls`, which must be under `/var/lib/majak` (the service
cannot write `/etc/site/majak`). `majak pin` prints its SPKI pin for the
DLG channel. Package: `wyga-majak`; both units restart on a change.
