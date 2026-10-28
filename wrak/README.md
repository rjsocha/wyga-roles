# wyga/wrak

Installs and configures wrak - the authoritative DNS registry with automatic
TLS - and the Knot slave that answers for its zones. Everything is declared
under `setup.wrak`; secrets come from `confidential.wrak`.

- `setup.wrak.config` runs the daemon part, `setup.wrak.knot` the Knot part.
  A host can have either or both.
- `wyga/host-policy` runs it after the VPN, so addresses on `vpn0` exist.

## Policy

```yaml
policy:
- hostname: host.dlg.example.net
  setup:
    wrak:
      config:                       # /etc/site/wrak/config.yaml as is
        listen:
          dns: ["127.0.0.1:53"]
          api: ["240.240.255.3:443"]
          admin: {socket: /run/wrak/admin.sock}
        db: {path: /var/lib/wrak/wrak.db}
        security:
          tsig:
            - name: wrak-transfer   # secret from confidential.wrak.tsig
        binder:
          - name: ci
            key: ["ssh-ed25519 AAAA... ci"]
        dns:
          nameserver: [{name: wrak, ns: ["ns.dlg.example.net."]}]
          slave: [{name: wrak, allow: ["127.0.0.1"], notify: ["65.21.129.237:53"]}]
        acme: {...}
        domains:
          - domain: wrak.dlg.example.net
            mode: api
            ip: ["240.240.255.3"]
            ns: wrak
            transfer: {mode: hidden, slave: wrak, tsig: wrak-transfer}
      static:                       # /etc/site/wrak/dns.d/<zone>.yaml
        local.example.net:
          ns: wrak
          transfer: {mode: hidden, slave: wrak, tsig: wrak-transfer}
          binder: [{name: ci}]
          record:
            - {name: "@", type: A, value: "100.100.100.100"}
      knot:
        listen: ["65.21.129.237@53"]
        primary: "127.0.0.1@53"
        tsig: wrak-transfer
```

## What the role manages

| Policy key | Result on the host |
| --- | --- |
| `config` | `/etc/site/wrak/config.yaml`, root:wrak 0640, merged with `confidential.wrak.config` |
| `static.<zone>` | `/etc/site/wrak/dns.d/<zone>.yaml`, root:wrak 0640; files of zones not listed are removed |
| `knot` | `/etc/knot/knot.conf`, root:knot 0640 |
| `confidential.wrak.tsig.<name>` | the secret of every `security.tsig` entry without `secret`, `file` or `env`, and of the Knot key |

`knot.zone` lists the zones Knot pulls. Without it, on a host that runs wrak,
the zones are every domain of `config` plus every `static` zone.

Packages: `wyga-wrak`, `knot`. The configuration is checked with
`wrak serve --test` and `knotc conf-check` before the services restart.
