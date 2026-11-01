# wyga/service/nginx

Takes nginx over: the package, modules, everything in `/etc/nginx` and every site.
Whatever the role does not know goes away. A site is written against the contract
below, not against the engine. Activates on `setup.nginx`; nginx does not belong in
`package.packages`.

```yaml
setup:
  nginx:
    engine: nginx-light        # nginx-light (default), nginx or nginx.org
    default: empty             # default_server answering 200 with no body: empty (default)
                               # on IPv4 and IPv6, empty-v4, empty-v6; or none
    modules:                   # off unless listed
      - http-echo
    config:                    # no key: the values of the packaged nginx.conf
      worker:
        processes: 2
        connections: 4096
      log:
        error: warn
        access: extended       # a format name, or off
        format:
          custom: '$host $remote_addr $status'
```

## Contract of a site

The same on every engine:

| A `vhost.conf` or a hook can rely on | |
|---|---|
| `include fastcgi_params;` | includes `SCRIPT_FILENAME`; set an own one after the include |
| `include proxy_params;` | `Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto` |
| `access_log ... extended;` | with `config.log.access: extended` |
| `nginx_site_name` | name of the site directory |
| `nginx_site_path` | that directory in the repository |
| `nginx_site_d` | `/etc/nginx/site.d/<name>/`, root:`nginx_user` 0750, the place of everything local to the site: `htpasswd`, includes; always there, its content is not touched, nothing loads it on its own |
| `nginx_user` | the worker user |

PHP is not configured by this role, setups differ: the `location`, `fastcgi_pass`
and the socket belong to the `vhost.conf` of the site.

## Engines

| | `nginx`, `nginx-light` | `nginx.org` |
|---|---|---|
| package source | distribution | nginx.org repository |
| site | `sites-available/<name>`, linked in `sites-enabled` | `conf.d/<name>.conf` |
| host configuration | `conf.d/*.conf` | `conf.d/*.conf` |
| worker user | `www-data` | `nginx` |
| module package | `libnginx-mod-<name>` | `nginx-module-<name>` |
| module enabled by | `modules-enabled/50-mod-<name>.conf` | `load_module` in `nginx.conf` |

Module names are the ones of the engine. A module not listed stays off, its package
stays installed: `nginx-light` depends on `libnginx-mod-http-echo`.

`nginx.conf` has the values of the packaged file, without its comments and with
two-space indentation. Distribution engines keep one file per release,
`templates/engine/debian/<distribution>/<version>/`, since each release ships its own
nginx: Debian 13, Ubuntu 24.04 and 26.04. A release without a file fails before anything
changes on the host.
`mime.types`, `fastcgi_params` and `proxy_params` are one set for all engines.

## Changing the engine

Change `engine`, and `modules` if the names differ, and apply.

- `nginx-light` and `nginx` swap packages in place. Configuration stays and nginx
  keeps running.
- Between distribution and nginx.org packaging the old installation goes first: module
  packages are checked, nginx stops, `/var/log/nginx` moves to
  `/var/log/nginx.<layout>.<timestamp>`, all nginx packages are purged, `/etc/nginx`,
  `/var/lib/nginx` and `/var/cache/nginx` go away, and the nginx.org repository goes
  too when leaving it. A normal run then builds everything again in the new layout,
  `init` and `ready` hooks included, so nginx is down until the run reaches the reload.

## Layout

```
site/<site>/nginx/<hostname>/    # has to exist: without it every site would go away
  nginx.conf        # optional, replaces the template, excludes setup.nginx.config;
                    # has to include the sites of the engine, use user {{ nginx_user }};
  mime.types        # optional, replaces the file of the role
  fastcgi_params    # optional, replaces the file of the role
  proxy_params      # optional, replaces the file of the role
  conf.d/*.conf     # host configuration, http level, templates
  <site name>/
    vhost.conf       # the vhost, a template: confidential is available
    file/           # anything the hooks need, by convention
    absent          # empty file: take this site down
    hook/
      init/*.yaml   # before the vhost
      ready/*.yaml  # after the reload, nginx serves the site
      remove/*.yaml # after the site is down, only with absent
```

Everything in a site except `vhost.conf` is optional, `host-default` is a reserved
site name. Hooks are ansible task files, run in name order, with the variables of the
contract. Any change made by a hook notifies `reload-nginx`; after `ready` and
`remove` the reload happens at the end of the run. A file a hook leaves in `/etc/nginx` outside
`nginx_site_d` goes away.

## Order of a run

1. the engine package (migrating if it changed), modules, `conf.d`, the convention
   files, `nginx.conf` (validated before it replaces the file)
2. the default site, `nginx_site_d`, `init` hooks, vhosts of active sites
3. everything unknown in `/etc/nginx` goes away
4. `nginx -t`, then the reload. A reload can fail while systemd reports success, e.g.
   a wildcard `listen` replaced by a specific address. Workers older than the
   configuration mean exactly that, and nginx is restarted
5. `ready` hooks, then `remove` hooks

A site that disappears from the repository runs no hook: nothing is known about it.
To remove a site with its hooks, add `absent`, apply, and delete the directory
afterwards. `remove` hooks run on every apply until then, so they have to be
idempotent.
