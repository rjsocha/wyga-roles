import base64
import hashlib

from ansible.errors import AnsibleFilterError

_STD = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
_BCRYPT = b'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'


def _salt(seed):
    raw = hashlib.sha256(seed.encode()).digest()[:16]
    return base64.b64encode(raw)[:22].translate(bytes.maketrans(_STD, _BCRYPT))


def lukd_basic(basic, hostname, rounds=10):
    """confidential.lukd.basic ({expose: {user: password}}) as the overlay
    of the lukd configuration: expose.<name>.auth.basic with bcrypt hashes.
    The salt comes from the host, the expose and the user, so a hash
    changes only with its password."""
    if not basic:
        return {}
    try:
        import bcrypt
    except ImportError:
        raise AnsibleFilterError("lukd_basic: the python module bcrypt is required on the controller")
    if not isinstance(basic, dict):
        raise AnsibleFilterError("lukd_basic: confidential.lukd.basic must be a map of exposes")
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
            entries.append(user + ':' + bcrypt.hashpw(password.encode(), salt).decode())
        expose[str(name)] = {'auth': {'basic': entries}}
    return {'expose': expose}


class FilterModule(object):
    def filters(self):
        return {'lukd_basic': lukd_basic}
