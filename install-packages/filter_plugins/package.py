import re
from pathlib import Path

import yaml
from ansible.errors import AnsibleFilterError
from ansible.utils.display import Display

_display = Display()

_PKG_NAME = r'[a-z0-9][a-z0-9.+-]+'

# Meta entries reference manifest files, not debian packages — allow ':' for
# namespacing (e.g. '.base:firmware') and '_' for readability.
_META_NAME = r'[a-z0-9][a-z0-9._:+-]*'
_META_RE = re.compile(r'^\.(?P<name>' + _META_NAME + r')$')

_APT_RE = re.compile(
    r'^'
    r'(?P<prefix>-{1,2})?'
    r'(?P<name>' + _PKG_NAME + r')'
    r'(?::(?P<arch>[a-z0-9]+))?'
    r'(?:=(?P<version>[^@%\s]+))?'
    r'(?:@(?P<distro>[a-z]+)(?:\((?P<versions>[^)]+)\))?)?'
    r'(?:%(?P<firmware>[a-z]+))?'
    r'$'
)

_MERGE_KEYS = ('prerequisite', 'require', 'repository', 'purge', 'enable')


def _parse_entry(entry):
    if not isinstance(entry, str):
        raise AnsibleFilterError(f"entry must be a string, got {entry!r}")
    if not entry:
        raise AnsibleFilterError("empty entry")

    if entry.startswith('.') or (entry.startswith('-') and entry[1:2] == '.'):
        m = _META_RE.match(entry)
        if not m:
            raise AnsibleFilterError(
                f"meta entry must be '.name' starting with '.' and using only "
                f"[a-z0-9._:+-] (no '-' prefix, no '@/=/%' suffixes; "
                f"gating goes inside the manifest): {entry!r}"
            )
        return {
            'kind':        'meta',
            'purge':       False,
            'purge_force': False,
            'name':        '.' + m.group('name'),
            'arch':        None,
            'version':     None,
            'distro':      None,
            'versions':    None,
            'firmware':    None,
        }

    m = _APT_RE.match(entry)
    if not m:
        raise AnsibleFilterError(f"cannot parse apt entry: {entry!r}")
    g = m.groupdict()
    prefix_len = len(g['prefix']) if g['prefix'] else 0
    versions = None
    if g['versions']:
        versions = [v.strip() for v in g['versions'].split(',') if v.strip()]
        if not versions:
            raise AnsibleFilterError(f"empty version list in {entry!r}")
    return {
        'kind':        'apt',
        'purge':       prefix_len >= 1,
        'purge_force': prefix_len >= 2,
        'name':        g['name'],
        'arch':        g['arch'],
        'version':     g['version'],
        'distro':      g['distro'],
        'versions':    versions,
        'firmware':    g['firmware'],
    }


def _distro_paths(name, platform, playbook_dir, role_path):
    distro = platform['distribution']
    version = platform['version']
    return [
        Path(playbook_dir) / 'local' / 'packages' / distro / version / name,
        Path(role_path) / 'packages' / distro / version / name,
        Path(playbook_dir) / 'site' / 'packages' / distro / version / name,
    ]


def _common_paths(name, playbook_dir, role_path):
    return [
        Path(playbook_dir) / 'local' / 'packages' / 'common' / name,
        Path(role_path) / 'packages' / 'common' / name,
        Path(playbook_dir) / 'site' / 'packages' / 'common' / name,
    ]


def _merge_into(dst, src):
    for k in _MERGE_KEYS:
        v = src.get(k)
        if v:
            dst.setdefault(k, []).extend(v)


def _load_manifest(paths, platform):
    merged = {}
    found = False
    for path in paths:
        if not path.is_file():
            continue
        with open(path) as f:
            data = yaml.safe_load(f)
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise AnsibleFilterError(f"manifest {path} must be a dict, got {type(data).__name__}")
        found = True
        _merge_into(merged, data)
        fw_block = (data.get('firmware') or {}).get(platform['firmware'])
        if fw_block:
            _merge_into(merged, fw_block)
    return merged if found else None


def _matches_platform(parsed, platform):
    if parsed['distro'] and parsed['distro'] != platform['distribution']:
        return False
    if parsed['versions'] and platform['version'] not in parsed['versions']:
        return False
    if parsed['arch'] and parsed['arch'] != platform['arch']['package']:
        return False
    if parsed['firmware'] and parsed['firmware'] != platform['firmware']:
        return False
    return True


def _apt_name(parsed):
    s = parsed['name']
    if parsed['arch']:
        s += ':' + parsed['arch']
    if parsed['version']:
        s += '=' + parsed['version']
    return s


def _resolve_apt_entries(items, platform, field):
    """Resolve apt entries from a manifest list field.

    For field='purge': returns (purge_list, purge_force_list).
    The 'purge:' field treats plain 'name' as purge (1 implicit minus) and
    '-name' as purge_force (2 minus = needs --allow-remove-essential).

    For other fields: returns (list, []). Entries with '-' prefix are
    rejected (purge has no meaning in install-oriented fields).
    """
    normal, force = [], []
    is_purge = field == 'purge'
    for entry in items or []:
        prep = '-' + entry if is_purge else entry
        parsed = _parse_entry(prep)
        if parsed['kind'] == 'meta':
            raise AnsibleFilterError(
                f"meta entry {entry!r} not allowed in manifest field {field!r}"
            )
        if not is_purge and parsed['purge']:
            raise AnsibleFilterError(
                f"entry {entry!r} with '-' prefix not allowed in {field!r}"
            )
        if not _matches_platform(parsed, platform):
            continue
        name = _apt_name(parsed)
        if parsed['purge_force']:
            force.append(name)
        else:
            normal.append(name)
    return normal, force


def _append_unique(lst, items):
    for it in items:
        if it not in lst:
            lst.append(it)


def package_resolve(entries, platform, playbook_dir, role_path):
    if not isinstance(entries, list):
        raise AnsibleFilterError(f"entries must be a list, got {type(entries).__name__}")
    if not isinstance(platform, dict):
        raise AnsibleFilterError(f"platform must be a dict, got {type(platform).__name__}")
    for k in ('firmware', 'arch', 'distribution', 'version'):
        if k not in platform:
            raise AnsibleFilterError(f"platform missing key {k!r}")

    queue = list(entries)
    seen = set()

    install = []
    prerequisite = []
    repos = []
    purges = []
    purges_force = []
    enables = []

    def _merge_manifest(manifest):
        prereq_n, prereq_f = _resolve_apt_entries(manifest.get('prerequisite'), platform, 'prerequisite')
        _append_unique(prerequisite, prereq_n)
        # prereq_f always empty: '-' prefix is rejected in non-purge fields
        purge_n, purge_f = _resolve_apt_entries(manifest.get('purge'), platform, 'purge')
        _append_unique(purges, purge_n)
        _append_unique(purges_force, purge_f)
        _append_unique(repos, manifest.get('repository', []))
        _append_unique(enables, manifest.get('enable', []))
        for req in manifest.get('require', []):
            if req not in seen:
                queue.append(req)

    while queue:
        raw = queue.pop(0)
        if raw in seen:
            continue
        seen.add(raw)

        parsed = _parse_entry(raw)

        if not _matches_platform(parsed, platform):
            continue

        if parsed['kind'] == 'meta':
            manifest = _load_manifest(
                _distro_paths(parsed['name'], platform, playbook_dir, role_path),
                platform,
            )
            if manifest is None:
                manifest = _load_manifest(
                    _common_paths(parsed['name'], playbook_dir, role_path),
                    platform,
                )
            if manifest is None:
                _display.warning(
                    f"meta {parsed['name']!r}: no manifest found "
                    f"for {platform['distribution']} {platform['version']}"
                )
                continue
            _merge_manifest(manifest)
            continue

        apt = _apt_name(parsed)
        if parsed['purge_force']:
            if apt not in purges_force:
                purges_force.append(apt)
        elif parsed['purge']:
            if apt not in purges:
                purges.append(apt)
        else:
            if apt not in install:
                install.append(apt)
            manifest = _load_manifest(
                _distro_paths(parsed['name'], platform, playbook_dir, role_path),
                platform,
            )
            if manifest is None:
                manifest = _load_manifest(
                    _common_paths(parsed['name'], playbook_dir, role_path),
                    platform,
                )
            if manifest is not None:
                _merge_manifest(manifest)

    install_set = set(install) | set(prerequisite)
    purges = [p for p in purges if p not in install_set]
    purges_force = [p for p in purges_force if p not in install_set]

    return {
        'firmware':     platform['firmware'],
        'package':      sorted(install),
        'prerequisite': list(dict.fromkeys(prerequisite)),
        'repository':   list(dict.fromkeys(repos)),
        'purge':        list(dict.fromkeys(purges)),
        'purge_force':  list(dict.fromkeys(purges_force)),
        'enable':       list(dict.fromkeys(enables)),
    }


class FilterModule(object):
    def filters(self):
        return {
            'package_resolve': package_resolve,
        }
