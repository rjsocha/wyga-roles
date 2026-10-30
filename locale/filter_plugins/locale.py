import re

from ansible.errors import AnsibleFilterError

_BUILTIN = ('C', 'C.UTF8', 'C.UTF-8', 'POSIX', 'NONE')
_ENTRY = re.compile(r'^\S+ \S+$')


def _normalize(name):
    locale, _, modifier = name.partition('@')
    language, _, charset = locale.partition('.')
    out = language
    if charset:
        out += '.' + re.sub(r'[^a-z0-9]', '', charset.lower())
    if modifier:
        out += '@' + modifier
    return out


def locale_generate(value):
    """The entries of setup.locale.generate to put in /etc/locale.gen:
    <locale> <charset>, sorted, without the locales the C library has built
    in. A value that is not a list of such entries is an error, as it would
    otherwise end in an empty /etc/locale.gen and no locales at all."""
    if not isinstance(value, (list, tuple)):
        raise AnsibleFilterError("setup.locale.generate must be a list, got %r" % (value,))
    out = set()
    for entry in value:
        entry = ' '.join(str(entry).split())
        if entry.split(' ')[0].upper() in _BUILTIN:
            continue
        if not _ENTRY.match(entry):
            raise AnsibleFilterError("setup.locale.generate: %r is not <locale> <charset>" % (entry,))
        out.add(entry)
    return sorted(out)


def locale_gen_active(content):
    """The active entries of the content of /etc/locale.gen, in the form of
    locale_generate. A package upgrade rewrites the comments of the file,
    only these lines say what it selects."""
    out = set()
    for line in content.splitlines():
        line = line.split('#')[0].strip()
        if line:
            out.add(' '.join(line.split()))
    return sorted(out)


def locale_names(value):
    """Locale names, or locale_generate entries, in the form of locale -a."""
    return sorted(set(_normalize(str(entry).split()[0]) for entry in value if str(entry).strip()))


def locale_default_names(default):
    """The locales setup.locale.default refers to. LANGUAGE is a list of
    languages, not a locale."""
    return [value for key, value in default.items() if str(key).upper() != 'LANGUAGE']


def locale_env_key(key):
    """The variable of a key of setup.locale.default: time is LC_TIME, while
    lang, language and lc_time name their variables themselves."""
    key = str(key).upper()
    if key in ('LANG', 'LANGUAGE') or key.startswith('LC_'):
        return key
    return 'LC_' + key


class FilterModule(object):
    def filters(self):
        return {
            'locale_generate': locale_generate,
            'locale_gen_active': locale_gen_active,
            'locale_names': locale_names,
            'locale_default_names': locale_default_names,
            'locale_env_key': locale_env_key,
        }
