import re

from ansible.errors import AnsibleFilterError

NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
RESERVED = ('JOB_NAME', 'JOB_CONFIG')


def scalar(key, value):
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (str, int, float)):
        return str(value)
    raise AnsibleFilterError("job: env %s: a value is a string, a number, a boolean or a list of them" % key)


def job_env(env):
    """Render the env map of a job as the lines of a systemd EnvironmentFile.

    A list becomes one value, its items joined with a tab. systemd expands
    no \\t or \\n in such a file; inside double quotes it takes the tab and
    the newline as they are and unescapes only the backslash and the quote.
    """
    if not isinstance(env, dict):
        raise AnsibleFilterError("job: env must be a map")
    lines = []
    for key, value in env.items():
        key = str(key)
        if not NAME.match(key):
            raise AnsibleFilterError("job: env %s: not a variable name" % key)
        if key in RESERVED:
            raise AnsibleFilterError("job: env %s: set by the unit" % key)
        if isinstance(value, (list, tuple)):
            items = [scalar(key, item) for item in value]
            if any('\t' in item for item in items):
                raise AnsibleFilterError("job: env %s: an item of a list holds a tab" % key)
            text = '\t'.join(items)
        else:
            text = scalar(key, value)
        if '\0' in text:
            raise AnsibleFilterError("job: env %s: holds a NUL" % key)
        lines.append('%s="%s"' % (key, text.replace('\\', '\\\\').replace('"', '\\"')))
    return lines


class FilterModule(object):
    def filters(self):
        return {'job_env': job_env}
