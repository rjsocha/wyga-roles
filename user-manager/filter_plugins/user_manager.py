import base64
import binascii
import os

from ansible.errors import AnsibleFilterError

GROUP_DEFAULTS = {'system': False, 'unique': True}
USER_DEFAULTS = {'shell': '/bin/bash', 'role': [], 'authorized': [], 'groups': [], 'forceChange': False}
INLINE = 'BASE64:'


def _merge(base, over):
    """combine(base, over, recursive=True, list_merge='append_rp') of
    Ansible: maps merge, a list of over is appended to the list of base
    with the elements of over removed from base first, anything else of
    over replaces."""
    out = dict(base)
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        elif isinstance(value, list) and isinstance(out.get(key), list):
            out[key] = [v for v in out[key] if v not in value] + list(value)
        else:
            out[key] = value
    return out


def wyga_users(host, onboard_password):
    """The catalogue of host.group and host.user (over host.append.user)
    as the role works on it: every group and user with the defaults
    filled in, the onboard password resolved, name set."""
    groups = {}
    for name, raw in (host.get('group') or {}).items():
        groups[str(name)] = dict(GROUP_DEFAULTS, **(raw if isinstance(raw, dict) else {}))
    merged = _merge((host.get('append') or {}).get('user') or {}, host.get('user') or {})
    if not isinstance(merged, dict):
        raise AnsibleFilterError("user must be a map keyed by the user name")
    users = {}
    for name, raw in merged.items():
        name = str(name)
        u = dict(USER_DEFAULTS, **(raw if isinstance(raw, dict) else {}))
        if u.get('password') == 'onboard':
            u['password'], u['forceChange'] = onboard_password, True
        u['name'] = name
        for key in ('authorized', 'groups'):
            if not isinstance(u[key], list):
                raise AnsibleFilterError("user %s: %s must be a list" % (name, key))
        for keyname in u['authorized']:
            if not isinstance(keyname, str):
                raise AnsibleFilterError("user %s: authorized holds a key name or BASE64:..., not %r" % (name, keyname))
        users[name] = u
    return {'groups': groups, 'users': users}


def _key_lines(playbook_dir, keys_dir, keyname):
    if keyname.startswith(INLINE):
        try:
            return [base64.b64decode(keyname[len(INLINE):], validate=True).decode().strip()]
        except (binascii.Error, ValueError):
            raise AnsibleFilterError("authorized key %s: not base64" % INLINE)
    path = os.path.join(playbook_dir, keys_dir, keyname)
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        raise AnsibleFilterError("File %s doesn't exist" % keyname)
    return text.rstrip('\r\n').splitlines()


def wyga_pools(users, playbook_dir, keys_dir='key/user', generated=None):
    """The content of /etc/ssh-pool/<user> for every user: the keys of
    authorized, each line of a key file prefixed by the options of the
    key (options.defaults, then options.<keyname>), in the order of the
    key names; inline keys (BASE64:...) last, newest first, without
    options. generated maps a user to public keys made on the host that
    other users' authorized lists get as inline keys. An empty content
    is a pool to remove."""
    users = {name: dict(u) for name, u in users.items()}
    for owner, keys in (generated or {}).items():
        for key in keys:
            inline = INLINE + base64.b64encode(key['key'].encode()).decode()
            for target in key.get('append') or []:
                if target not in users:
                    raise AnsibleFilterError("user %s: keygen append names unknown user %s" % (owner, target))
                users[target]['authorized'] = list(users[target]['authorized']) + [inline]
    pools = {}
    for name, u in users.items():
        options = (u.get('options') or {}) if isinstance(u.get('options'), dict) else {}
        files, inline = {}, []
        for keyname in u['authorized']:
            lines = _key_lines(playbook_dir, keys_dir, keyname)
            if keyname.startswith(INLINE):
                inline = lines + inline
                continue
            opts = list(options.get('defaults') or []) + list(options.get(keyname) or [])
            prefix = ','.join(str(o) for o in opts)
            if prefix:
                lines = [prefix + ' ' + line for line in lines]
            files[keyname] = lines
        parts = [files[k] for k in sorted(files)] + ([inline] if inline else [])
        pools[name] = ''.join('\n'.join(lines) + '\n' for lines in parts if lines)
    return pools


def wyga_keygen_of(user):
    """The keygen entries of a user, each with the user name."""
    out = []
    for k in user.get('keygen') or []:
        if not isinstance(k, dict):
            raise AnsibleFilterError("user %s: keygen must be a list of maps" % user['name'])
        out.append(dict(k, user=user['name']))
    return out


def wyga_generated(results):
    """The slurped public keys of the generated keys, by user: what
    wyga_pools takes as generated."""
    out = {}
    for r in results:
        key = r['key']
        content = base64.b64decode(r['content']).decode()
        out.setdefault(key['user'], []).append({'key': content, 'append': key.get('append') or []})
    return out


class FilterModule(object):
    def filters(self):
        return {
            'wyga_users': wyga_users,
            'wyga_pools': wyga_pools,
            'wyga_keygen_of': wyga_keygen_of,
            'wyga_generated': wyga_generated,
        }
