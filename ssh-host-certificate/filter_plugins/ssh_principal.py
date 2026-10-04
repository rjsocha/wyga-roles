import re

from ansible.errors import AnsibleFilterError

_PRINCIPAL = re.compile(r'^[A-Za-z0-9*][A-Za-z0-9._:*-]*$')


def _addresses(entry):
    ip = entry.get('ip')
    if ip is None:
        return []
    if isinstance(ip, str):
        ip = [ip]
    return [str(a).split('/')[0] for a in ip]


def _marked(entries, default, what):
    out = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        have = _addresses(entry)
        mark = entry.get('certificate', default)
        if mark is True:
            out += have
        elif mark is False or mark is None:
            continue
        else:
            if isinstance(mark, str):
                mark = [mark]
            for a in mark:
                a = str(a).split('/')[0]
                if a not in have:
                    raise AnsibleFilterError("%s: certificate address %s is not an address of the entry" % (what, a))
                out.append(a)
    return out


def ssh_host_principals(host):
    """The principals of the SSH host certificate of a host policy.

    setup.ssh.host.principal lists names, addresses and the keywords
    hostname, vpn and address; without the key it is [hostname]. vpn is
    the addresses of setup.vpn (an entry limits them with certificate:
    false or a list), address the addresses of the network interfaces
    marked certificate: true or with a list."""
    setup = host.get('setup') or {}
    ssh = (setup.get('ssh') or {}).get('host') or {}
    listed = ssh.get('principal', ['hostname'])
    if isinstance(listed, str) or not isinstance(listed, list):
        raise AnsibleFilterError("setup.ssh.host.principal must be a list")
    keyword = {
        'hostname': lambda: [host['hostname']],
        'vpn': lambda: _marked(setup.get('vpn'), True, 'setup.vpn'),
        'address': lambda: _marked((host.get('network') or {}).get('interface'), False, 'network.interface'),
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


class FilterModule(object):
    def filters(self):
        return {'ssh_host_principals': ssh_host_principals}
