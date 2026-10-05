import base64
import binascii
import hashlib
import os
import re

import yaml
from ansible.errors import AnsibleFilterError

_PRINCIPAL = re.compile(r'^[A-Za-z0-9*][A-Za-z0-9._:*-]*$')


def _addresses(entry):
    ip = entry.get('ip')
    if ip is None:
        return []
    if isinstance(ip, str):
        ip = [ip]
    return [str(a).split('/')[0] for a in ip]


def _marked(entry, default, what):
    """The addresses of entry its certificate mark selects; None when the
    mark turns the entry off."""
    have = _addresses(entry)
    mark = entry.get('certificate', default)
    if mark is True:
        return have
    if mark is False or mark is None:
        return None
    if isinstance(mark, str):
        mark = [mark]
    out = []
    for a in mark:
        a = str(a).split('/')[0]
        if a not in have:
            raise AnsibleFilterError("%s: certificate address %s is not an address of the entry" % (what, a))
        out.append(a)
    return out


def _interfaces(host):
    out = []
    for entry in (host.get('network') or {}).get('interface') or []:
        if isinstance(entry, dict):
            out += _marked(entry, False, 'network.interface') or []
    return out


def _vpn_domains(playbook_dir, name):
    path = os.path.join(playbook_dir, 'vpn', 'nebula', str(name), 'config.yaml')
    try:
        with open(path) as f:
            config = yaml.safe_load(f) or {}
    except OSError as e:
        raise AnsibleFilterError("setup.vpn %s: %s" % (name, e))
    alias = config.get('alias') or []
    if isinstance(alias, str):
        alias = [alias]
    if not isinstance(alias, list):
        raise AnsibleFilterError("setup.vpn %s: alias must be a list of domains" % name)
    return [config.get('domain') or 'vpn'] + [str(a) for a in alias]


def _vpn(host, playbook_dir):
    out = []
    for entry in (host.get('setup') or {}).get('vpn') or []:
        if not isinstance(entry, dict) or 'name' not in entry:
            continue
        addresses = _marked(entry, True, 'setup.vpn')
        if addresses is None:
            continue
        for domain in _vpn_domains(playbook_dir, entry['name']):
            out.append('%s.%s' % (entry.get('hostname') or host['hostname'], domain))
        out += addresses
    return out


def ssh_host_principals(host, playbook_dir):
    """The principals of the SSH host certificate of a host policy.

    setup.ssh.host.principal lists names, addresses and the keywords
    hostname, vpn and address; without the key it is [hostname]. vpn is,
    for every entry of setup.vpn, the name of the host in the VPN
    (<hostname>.<domain>, as wyga/nebula-vpn names it, and the same under
    every domain of alias in the config of the VPN) and its addresses;
    certificate: false on the entry leaves it out, a list limits the
    addresses. address is the addresses of the network interfaces marked
    certificate: true or with a list."""
    setup = host.get('setup') or {}
    ssh = (setup.get('ssh') or {}).get('host') or {}
    listed = ssh.get('principal', ['hostname'])
    if isinstance(listed, str) or not isinstance(listed, list):
        raise AnsibleFilterError("setup.ssh.host.principal must be a list")
    keyword = {
        'hostname': lambda: [host['hostname']],
        'vpn': lambda: _vpn(host, playbook_dir),
        'address': lambda: _interfaces(host),
    }
    out = []
    for entry in listed:
        entry = str(entry)
        for principal in keyword[entry]() if entry in keyword else [entry]:
            if not _PRINCIPAL.match(principal):
                raise AnsibleFilterError("setup.ssh.host.principal: invalid principal %r" % principal)
            if principal not in out:
                out.append(principal)
    if listed and not out:
        raise AnsibleFilterError("setup.ssh.host.principal %s gives no principal: the host has no such addresses" % listed)
    return out


_INTERVAL = re.compile(r'^(?:[0-9]+[smhdw])+$')
_UNIT = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}


def ssh_interval_seconds(value):
    """An interval in the form ssh-keygen -V takes (26w, 90d, 1w2d) as
    seconds."""
    value = str(value)
    if not _INTERVAL.match(value):
        raise AnsibleFilterError("invalid interval %r: use a number and s, m, h, d or w, as in 26w or 1w2d" % value)
    return sum(int(n) * _UNIT[u] for n, u in re.findall(r'([0-9]+)([smhdw])', value))


def ssh_fingerprint_hex(line):
    """The SHA256 fingerprint of a public key line (type, base64 blob,
    comment), in hex: the form that names a file."""
    fields = str(line).split()
    if len(fields) < 2:
        raise AnsibleFilterError("ssh_fingerprint_hex: not a public key line")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError):
        raise AnsibleFilterError("ssh_fingerprint_hex: not a public key line")
    return hashlib.sha256(blob).hexdigest()


class FilterModule(object):
    def filters(self):
        return {
            'ssh_host_principals': ssh_host_principals,
            'ssh_interval_seconds': ssh_interval_seconds,
            'ssh_fingerprint_hex': ssh_fingerprint_hex,
        }
