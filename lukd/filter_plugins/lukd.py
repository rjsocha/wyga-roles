import base64
import ctypes
import ctypes.util
import hashlib

from ansible.errors import AnsibleFilterError

_STD = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
_BCRYPT = b'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'


def _salt(seed):
    raw = hashlib.sha256(seed.encode()).digest()[:16]
    return base64.b64encode(raw)[:22].translate(bytes.maketrans(_STD, _BCRYPT))


def _libcrypt(password, salt):
    """bcrypt through crypt(3) of the system libcrypt; None when the
    library is missing or has no bcrypt."""
    name = ctypes.util.find_library('crypt')
    if not name:
        return None
    try:
        lib = ctypes.CDLL(name)
    except OSError:
        return None
    lib.crypt.restype = ctypes.c_char_p
    lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    out = lib.crypt(password, salt)
    if not out or not out.startswith(salt):
        return None
    return out


def _bcrypt(password, salt):
    out = _libcrypt(password, salt)
    if out is not None:
        return out
    try:
        import bcrypt
    except ImportError:
        raise AnsibleFilterError("lukd_basic: no bcrypt on the controller: neither crypt(3) of libcrypt nor the python module bcrypt has it")
    return bcrypt.hashpw(password, salt)


def _sets(config):
    """The user set each expose of the policy configuration names with
    auth.basic: <set>, the users of confidential.lukd.auth.basic.<set>."""
    out = {}
    for name, expose in ((config or {}).get('expose') or {}).items():
        auth = (expose or {}).get('auth') if isinstance(expose, dict) else None
        if isinstance(auth, dict) and 'basic' in auth:
            s = auth['basic']
            if not isinstance(s, str) or not s:
                raise AnsibleFilterError("lukd_basic: expose.%s.auth.basic must name a user set of confidential.lukd.auth.basic" % name)
            out[str(name)] = s
    return out


def lukd_basic(basic, hostname, rounds=10, config=None):
    """confidential.lukd.auth.basic ({set: {user: password}}) as the overlay
    of the lukd configuration: expose.<name>.auth.basic with the bcrypt
    hashes of the set the policy expose names with auth.basic: <set>. The
    salt comes from the host, the set and the user, so a hash changes only
    with its password. Every set named must exist and every set must be
    named."""
    basic = basic or {}
    if not isinstance(basic, dict):
        raise AnsibleFilterError("lukd_basic: confidential.lukd.auth.basic must be a map of user sets")
    sets = _sets(config)
    missing = sorted(set(sets.values()) - set(map(str, basic)))
    if missing:
        raise AnsibleFilterError("lukd_basic: user set %s is named by an expose but missing in confidential.lukd.auth.basic" % ', '.join(missing))
    unused = sorted(set(map(str, basic)) - set(sets.values()))
    if unused:
        raise AnsibleFilterError("lukd_basic: confidential.lukd.auth.basic.%s: no expose names this user set" % ', '.join(unused))
    if not sets:
        return {}
    rounds = int(rounds)
    if not 4 <= rounds <= 31:
        raise AnsibleFilterError("lukd_basic: bcrypt rounds must be 4..31")
    hashed = {}
    for name, users in basic.items():
        if not isinstance(users, dict) or not users:
            raise AnsibleFilterError("lukd_basic: %s must be a map of user: password" % name)
        entries = []
        for user, password in users.items():
            user, password = str(user), str(password)
            if not user or ':' in user or not password:
                raise AnsibleFilterError("lukd_basic: %s: empty user or password, or a colon in the user" % name)
            if len(password.encode()) > 72:
                raise AnsibleFilterError("lukd_basic: %s: password of %s longer than 72 bytes" % (name, user))
            salt = b'$2b$%02d$' % rounds + _salt('%s/%s/%s' % (hostname, name, user))
            entries.append(user + ':' + _bcrypt(password.encode(), salt).decode())
        hashed[str(name)] = entries
    return {'expose': {expose: {'auth': {'basic': hashed[s]}} for expose, s in sets.items()}}


class FilterModule(object):
    def filters(self):
        return {'lukd_basic': lukd_basic}
