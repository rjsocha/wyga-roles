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


def lukd_basic(basic, hostname, rounds=10):
    """confidential.lukd.auth.basic ({expose: {user: password}}) as the overlay
    of the lukd configuration: expose.<name>.auth.basic with bcrypt hashes.
    The salt comes from the host, the expose and the user, so a hash
    changes only with its password."""
    if not basic:
        return {}
    if not isinstance(basic, dict):
        raise AnsibleFilterError("lukd_basic: confidential.lukd.auth.basic must be a map of exposes")
    rounds = int(rounds)
    if not 4 <= rounds <= 31:
        raise AnsibleFilterError("lukd_basic: bcrypt rounds must be 4..31")
    expose = {}
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
        expose[str(name)] = {'auth': {'basic': entries}}
    return {'expose': expose}


class FilterModule(object):
    def filters(self):
        return {'lukd_basic': lukd_basic}
