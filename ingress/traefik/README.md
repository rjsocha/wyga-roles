# wyga/ingress/traefik

Renders a [Traefik](https://traefik.io/) ingress configuration (static + dynamic)
from a declarative policy and installs the `traefik-ingress` package.

All configuration lives under `setup.ingress.traefik` in the host policy and is
exposed to the templates as `IngressConfig` after being processed by the
`process_ingress_config` filter (`filter_plugins/ingress.py`).

```yaml
setup:
  ingress:
    traefik:
      log: error
      provider:
        file:
      entrypoint:
        http:  default
        https: default
      acme:
        http: true
      vhost:
        - url: http2s://example.com
          config:
            upstream: http://10.0.0.10:8080
```

---

## Entrypoints

`entrypoint` is a **map** of named entrypoints. The model is **replacement**:

- If `entrypoint` is **omitted**, the defaults are used:
  `http` on `:80` and `https` on `:443`.
- If `entrypoint` is **present**, it is the complete set. To disable the public
  `https`, simply do not list it.

```yaml
entrypoint:
  http:  { type: http }
  https: { type: https }
  vpn:   { type: http,  bind: 100.100.200.200 }
  vpns:  { type: https, bind: 100.100.200.200 }
```

### Per-entrypoint keys

| key        | required | default                  | meaning |
|------------|----------|--------------------------|---------|
| `type`     | yes      | -                        | `http` or `https`. Decides TLS/http3 handling. |
| `address` / `bind` | no | `""` (empty)         | Bind address. Empty -> `:PORT` (listens on IPv4 **and** IPv6). `0.0.0.0` -> IPv4 only. |
| `port`     | no       | `80` (http) / `443` (https) | Listen port. |
| `default`  | no       | `false`                  | Marks the entrypoint as `asDefault` (used by routers without an explicit entrypoint, e.g. docker label routing). Only rendered when `true`. |
| `http3`    | no       | `true`                   | Enables HTTP/3 (https-type only). Set `false` to disable. |
| `redirect` | no       | -                        | Redirect to another entrypoint (see below). |

`address` accepts the alias `bind`.

### `default` shorthand

`http: default` / `https: default` expand to the built-in defaults for that
name. Only `http` and `https` have a built-in default.

```yaml
entrypoint:
  http:  default          # -> { type: http,  address: "", port: 80,  redirect: https:1 }
  https: default          # -> { type: https, address: "", port: 443, default: true }
  vpns:  { type: https, bind: 100.100.200.200 }
```

### asDefault

`asDefault` is rendered **only** as `asDefault: true`, and only when `default`
resolves to true. The built-in `https` entrypoint has `default: true`; everything
else defaults to `false` unless you set `default: true` explicitly. If no
entrypoint is marked default, Traefik falls back to using all of them.

### Entrypoint redirect

A `redirect` on an entrypoint emits a Traefik `http.redirections` block. Compact
syntax: `<target-entrypoint>[:<priority>]`.

```yaml
entrypoint:
  http:  { type: http, redirect: https }      # redirect to entrypoint https
  vpn:   { type: http, redirect: vpns:1 }      # redirect to vpns, router priority 1
  https: { type: https }
  vpns:  { type: https, bind: 100.100.200.200 }
```

- No priority -> the `priority` field is omitted -> Traefik default (MaxInt-1,
  the redirect catches everything).
- `:N` -> low priority, so explicit routers on the http entrypoint win (e.g. the
  ACME HTTP-01 challenge). This is why the **built-in** `http` entrypoint ships
  with `redirect: https:1`.
- The full form `redirect: { to: vpns, priority: 1 }` is also accepted.
- The redirect target must be a defined entrypoint (validated).

The redirect is **explicit only** - there is no global `http2https` flag and the
docker feature does not auto-inject it. A gateway host that needs http->https
adds the redirect on its `http` entrypoint (the default already does).

---

## Providers

### file

```yaml
provider:
  file:
    watch: false        # default false
```

Enables the file provider that serves the rendered dynamic config (vhosts,
redirects, middlewares, static TLS certificates, TLS options). Required for
vhosts and `tls.certificates`.

### docker

```yaml
provider:
  docker:
    endpoint: unix:///var/run/docker.sock   # default
    exposedByDefault: false                  # default (forced true when feature expose.vhost is on)
    feature:
      - expose.vhost
```

| key               | default                       | meaning |
|-------------------|-------------------------------|---------|
| `endpoint`        | `unix:///var/run/docker.sock` | Docker socket. |
| `exposedByDefault`| `false`                       | Honoured only when `feature: expose.vhost` is **not** set (the feature forces `true`). |
| `feature`         | -                             | List of opt-in features. |

A bare `docker:` keeps Traefik defaults (only containers with
`traefik.enable=true`, no custom rule), so existing docker hosts are unchanged.

#### feature: expose.vhost

Opt-in label-based routing adapted from local-gateway. When enabled:

- `exposedByDefault` is forced to `true`,
- a `defaultRule` derives the router rule from the container's `expose.vhost`
  label,
- `constraints` limits exposure to containers carrying `traefik.enable` or
  `expose.vhost`.

Container label syntax (`expose.vhost`, comma-separated):

| label value           | rule |
|-----------------------|------|
| `app.example.com`     | `Host(app.example.com)` |
| `*.example.com`       | `HostRegexp(^<label>.example.com$)` - any subdomain |
| `costam-*.example.com`| `HostRegexp(^costam-<label>.example.com$)` |
| (no `expose.vhost`)   | falls back to `Host(<container name>)` (Traefik's native default) |

`*` matches a label segment (`[0-9a-z][0-9a-z-]*`); the prefix is literal. A
container may list several hosts: `expose.vhost: a.example.com,*.b.example.com`.

---

## Vhosts

`vhost` is a list of routes. Each entry has a top-level `url` and a `config`.

```yaml
vhost:
  - url: http2s://example.com
    config:
      upstream: http://10.0.0.10:8080
```

`url` scheme:

| scheme    | behaviour |
|-----------|-----------|
| `http://` | served on http only |
| `https://`| served on https (TLS) only |
| `http2s://`| served on both; http redirects to https (covers `http://` + `https://`) |

### config keys

| key        | meaning |
|------------|---------|
| `upstream` / `backend` | Backend. String URL (`http://host:port`) or `{ servers: [ { url, weight } ], health: { path, interval, timeout, host } }`. `upstream` and `backend` are aliases; use one. |
| `san`      | TLS SAN list. Defaults to the host(s) from `url`. |
| `tls`      | Cert resolver name (an ACME provider name, or `http`, or `none`). Defaults to `http` if the http resolver exists, else `none`. |
| `via`      | Entrypoint(s) this vhost is served on (string or list). Overrides the default `http`/`https` selection (see below). |
| `redirect` | Additional hostnames that 301 to this vhost's canonical host. |

### via (entrypoint selection)

By default a vhost is served on `http` and/or `https` (from the url scheme).
`via` overrides which entrypoints are used; the url scheme still decides the
router shape (http vs https). The named entrypoints are partitioned by `type`.

```yaml
vhost:
  - url: https://internal.vm        # served only over VPN
    config:
      via: vpns
      upstream: http://10.0.0.5:8080
```

Validation: every name in `via` must be a defined entrypoint, and the vhost must
have an entrypoint matching its scheme (e.g. an https url needs an https-type
entrypoint in `via`).

---

## Redirects

### Pure redirects (sugar)

Top-level `redirect` is a list of `{ to, from }` rules. Each desugars to a
redirect-only vhost. Use it for clean host -> address redirects with no backend.

```yaml
redirect:
  - to: https://new.example.com     # bare target -> https:// is assumed
    from:                            # string or list
      - old.example.com             # bare host -> redirects from http AND https
      - http2s://www.example.com    # same as bare (both schemes)
      - https://secure-only.com     # explicit scheme -> that scheme only
```

- A bare `from` host (or `http2s://`) redirects from **both** http and https.
- An explicit `http://` / `https://` `from` redirects from that scheme only.
- Several `from` entries in one rule all point to the same `to`.
- Path is preserved (`/foo?bar` is carried over to the target).
- For an https source you need a certificate for that host (TLS terminates
  before the redirect).

### Redirect-only vhost (underlying form)

The sugar expands to this; you can also write it directly:

```yaml
vhost:
  - to: https://new.example.com
    config:
      url:
        - http://old.example.com
        - https://old.example.com
```

---

## Dashboard

```yaml
dashboard:
  url: https://dashboard.example.com
  via: vpns          # optional: force a specific entrypoint
  tls: dns           # cert resolver name, or none
```

- Without `via`, the entrypoint is derived from the `url` scheme
  (`http` / `https` / `http2s`).
- With `via` (alias of `entrypoint`), the dashboard is forced onto that
  entrypoint; its `type` decides the router shape (https -> TLS). The name must
  be a defined entrypoint.
- Basic-auth users come from `confidential.ingress.dashboard.users`.

---

## TLS

### Static certificates

```yaml
tls:
  store: /etc/site/tls/blog
  certificates:
    - /etc/site/tls/blog/vpn.example.com.pem   # absolute path, any extension
    - blogs.vpn.example.com                      # relative -> <store>/blogs.vpn.example.com.pem
    - cert: foo                                  # dict form (relative resolved too)
      key:  foo-key
```

- A string entry uses the same file for cert and key (combined PEM).
- A dict entry takes `cert` (required) and `key` (defaults to `cert`).
- An **absolute** path (`/...`) is used verbatim, with any extension.
- A **relative** path is resolved to `<tls.store>/<value>.pem` (the `.pem`
  suffix is enforced). A relative path without `tls.store` is an error.
- Traefik matches a static certificate to a request by SNI, so a vhost served
  with `tls: none` still gets the static cert when the host matches.
- `tls.certificates` **requires** `provider.file` (validated).

TLS options (`tls.options.default`) are fixed to the Mozilla intermediate
profile (TLS 1.2+, modern cipher suite).

### ACME

```yaml
acme:
  http: true                 # HTTP-01 challenge resolver, named "http"
  dns:
    - provider: digitalocean # DNS-01 challenge
      name: dns              # resolver name (defaults to provider)
      check: true
      delay: 5
  key: RSA2048               # key type
  staging: false             # use Let's Encrypt staging
  resolvers:                 # custom DNS resolvers for the propagation check
    - 1.1.1.1:53
```

DNS provider credentials come from `confidential.ingress.dns` (written to an env
file for Traefik).

---

## Other keys

| key             | default                | meaning |
|-----------------|------------------------|---------|
| `log`           | `error`                | Traefik log level. |
| `runtime.path`  | `ingress_default_runtime_dir` | Directory for the rendered config. |
| `runtime.forwarded` | -                  | `forwardedHeaders` on every entrypoint: `{ insecure: true }` or `{ trust: [ cidr, ... ] }`. |
| `runtime.keep`  | `[]`                   | Extra runtime files to keep during cleanup. |

---

## Files

| file | purpose |
|------|---------|
| `tasks/main.yaml`, `tasks/execute.yaml` | install + render + cleanup |
| `filter_plugins/ingress.py` | `process_ingress_config` - normalises and expands the policy |
| `templates/traefik/main` | static config (`config.yaml`): entrypoints, providers, ACME |
| `templates/traefik/runtime` | shared dynamic config: middlewares, TLS options, static certificates |
| `templates/traefik/vhost` | per-vhost routers/services |
| `templates/traefik/redirect` | redirect (move) chains |
| `templates/traefik/tls-domains` | list of domains needing certificates |
