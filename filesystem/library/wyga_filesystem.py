#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = """
---
module: wyga_filesystem
short_description: Filesystems and swap of a host as the policy declares them.
description:
  - btrfs - a filesystem labelled with the key on 'device' (a block
    device or a regular file, then mounted through loop), made when the
    device has no signature, grown to the device when the device is
    larger, relabelled when the label differs; never reformatted. Each
    entry of 'volume' is a subvolume, created when missing, with the
    owner, group and mode of its root when given.
  - swap - a swap area labelled with the key on 'device' (a block
    device, or a regular file made with 'size' when missing), activated.
  - Returns the mounts for the fstab; the role applies them.
  - Check mode reports the plan without running it.
options:
  btrfs:
    description: "{label: {device, options: [], volume: {name: {mount, options: [], owner, group, mode}}}}"
    type: dict
  swap:
    description: "{label: {device, size}}"
    type: dict
"""

RETURN = """
plan:
  description: The actions taken, or to take in check mode.
  returned: always
  type: list
mounts:
  description: "[{path, src, fstype, opts}] for the fstab, swap with path none."
  returned: always
  type: list
"""

import os
import re
import stat
import tempfile

from ansible.module_utils.basic import AnsibleModule

BTRFS_MAGIC = 0x9123683E
_LABEL = re.compile(r'^[^\x00/\n]{1,255}$')
_VOLUME = re.compile(r'^[@a-zA-Z0-9][a-zA-Z0-9_.@+-]*$')
_UNITS = {'': 1, 'B': 1, 'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30, 'T': 1 << 40, 'P': 1 << 50}


def to_bytes(size, what):
    m = re.match(r'^\s*(\d+(?:\.\d+)?)\s*([KMGTP]?)(?:I?B)?\s*$', str(size), re.I)
    if not m:
        raise ValueError("%s: size %r is not a number with a unit of K, M, G, T or P" % (what, size))
    return int(float(m.group(1)) * _UNITS[m.group(2).upper()])


class Host(object):
    def __init__(self, module):
        self.module = module
        self.check = module.check_mode
        self.plan = []
        self.mounts = []

    def run(self, args, ok=(0,), **kw):
        rc, out, err = self.module.run_command(args, **kw)
        if rc not in ok:
            self.module.fail_json(msg="%s: %s" % (' '.join(args), (err or out).strip()))
        return out

    def act(self, what, args, **kw):
        self.plan.append(what)
        if not self.check:
            self.run(args, **kw)


def blkid(host, device):
    """TYPE and LABEL of the signature on device, {} without one."""
    out = host.run(['blkid', '-p', '-o', 'export', device], ok=(0, 2))
    tags = {}
    for line in out.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            tags[key] = re.sub(r'\\(.)', r'\1', value)
    return tags


def device_kind(host, what, device):
    """'block' or 'file' with the real path; fails on anything else."""
    if not isinstance(device, str) or not device.startswith('/'):
        host.module.fail_json(msg="%s: device must be an absolute path" % what)
    real = os.path.realpath(device)
    try:
        st = os.stat(real)
    except OSError:
        if host.check:
            return 'absent', real
        host.module.fail_json(msg="%s: device %s does not exist" % (what, device))
    if stat.S_ISBLK(st.st_mode):
        return 'block', real
    if stat.S_ISREG(st.st_mode):
        return 'file', real
    host.module.fail_json(msg="%s: device %s is neither a block device nor a regular file" % (what, device))


def device_size(host, kind, real):
    if kind == 'file':
        return os.stat(real).st_size
    return int(host.run(['blockdev', '--getsize64', real]).strip())


def mounted_at(host, real, kind):
    """{mountpoint: options} of every mount of the device."""
    source = real
    if kind == 'file':
        out = host.run(['losetup', '-n', '-O', 'NAME', '-j', real])
        loops = out.split()
        if not loops:
            return {}
        source = loops[0]
    out = host.run(['findmnt', '-rno', 'TARGET,OPTIONS', '-S', source], ok=(0, 1))
    mounts = {}
    for line in out.splitlines():
        target, _, options = line.partition(' ')
        mounts[target] = options
    return mounts


def fstab_source(kind, real, label):
    """A block device goes into the fstab by its label, which survives
    any renumbering; a file by its path."""
    return real if kind == 'file' else 'LABEL=' + label


def options_of(spec, what):
    options = spec.get('options') or []
    if isinstance(options, str):
        options = [options]
    if not isinstance(options, list) or not all(isinstance(o, str) and o and ',' not in o for o in options):
        raise ValueError("%s: options must be a list of mount options" % what)
    return options


class TopLevel(object):
    """The top-level subvolume of a btrfs mounted on demand."""

    def __init__(self, host, real, kind):
        self.host, self.real, self.kind, self.path = host, real, kind, None

    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix='wyga-filesystem-')
        opts = 'subvol=/' + (',loop' if self.kind == 'file' else '')
        self.host.run(['mount', '-t', 'btrfs', '-o', opts, self.real, self.path])
        return self.path

    def __exit__(self, *exc):
        self.host.run(['umount', self.path])
        os.rmdir(self.path)
        return False


def apply_btrfs(host, label, spec):
    what = 'btrfs.%s' % label
    kind, real = device_kind(host, what, spec.get('device'))
    try:
        fs_options = options_of(spec, what)
    except ValueError as e:
        host.module.fail_json(msg=str(e))
    volumes = spec.get('volume') or {}
    if not isinstance(volumes, dict) or not volumes:
        host.module.fail_json(msg="%s: volume must be a map of at least one subvolume" % what)
    for name, vol in volumes.items():
        if not _VOLUME.match(str(name)):
            host.module.fail_json(msg="%s.volume.%s: not a valid subvolume name" % (what, name))
        if not isinstance(vol, dict) or not isinstance(vol.get('mount'), str) or not vol['mount'].startswith('/'):
            host.module.fail_json(msg="%s.volume.%s: mount must be an absolute path" % (what, name))

    if kind == 'absent':
        host.plan.append("mkfs.btrfs %s on %s once wyga/storage made it" % (label, spec['device']))
        for name in volumes:
            host.plan.append("subvolume %s on %s" % (name, label))
        _emit_mounts(host, label, real, 'block', fs_options, volumes)
        return
    sig = blkid(host, real)
    fresh = not sig.get('TYPE')
    if fresh:
        host.act("mkfs.btrfs %s on %s" % (label, real), ['mkfs.btrfs', '-q', '-L', label, real])
    elif sig['TYPE'] != 'btrfs':
        host.module.fail_json(msg="%s: %s holds %s, refusing to touch it" % (what, spec['device'], sig['TYPE']))
    if host.check and fresh:
        for name in volumes:
            host.plan.append("subvolume %s on %s" % (name, label))
        _emit_mounts(host, label, real, kind, fs_options, volumes)
        return

    mounts = mounted_at(host, real, kind)
    mounted_volumes = {}
    for target, options in mounts.items():
        m = re.search(r'(?:^|,)subvol=/([^,]*)', options)
        if m:
            mounted_volumes.setdefault(m.group(1), target)

    missing = [n for n in volumes if n not in mounted_volumes]
    relabel = not fresh and sig.get('LABEL') != label
    size_dev = device_size(host, kind, real)
    grow = False
    if not fresh:
        if kind == 'file':
            loops = host.run(['losetup', '-n', '-O', 'NAME', '-j', real]).split()
            for loop in loops:
                host.run(['losetup', '-c', loop])
        out = host.run(['btrfs', 'filesystem', 'show', '--raw', real])
        m = re.search(r'devid\s+\d+\s+size\s+(\d+)', out)
        grow = bool(m) and size_dev > int(m.group(1))

    if missing or relabel or grow or any(_perm_wanted(volumes[n]) for n in volumes):
        with TopLevel(host, real, kind) as top:
            if relabel:
                host.act("label %s as %s" % (real, label), ['btrfs', 'filesystem', 'label', top, label])
            if grow:
                host.act("resize %s to the device" % label, ['btrfs', 'filesystem', 'resize', 'max', top])
            for name in volumes:
                path = os.path.join(top, name)
                if not os.path.isdir(path):
                    host.act("subvolume %s on %s" % (name, label), ['btrfs', 'subvolume', 'create', path])
                    if host.check:
                        continue
                _apply_perm(host, what, name, volumes[name], path)
    _emit_mounts(host, label, real, kind, fs_options, volumes)


def _perm_wanted(vol):
    return any(k in vol for k in ('owner', 'group', 'mode'))


def _apply_perm(host, what, name, vol, path):
    if not _perm_wanted(vol):
        return
    st = os.stat(path)
    uid, gid = st.st_uid, st.st_gid
    if 'owner' in vol:
        import pwd
        try:
            uid = pwd.getpwnam(str(vol['owner'])).pw_uid
        except KeyError:
            host.module.fail_json(msg="%s.volume.%s: no such user %s" % (what, name, vol['owner']))
    if 'group' in vol:
        import grp
        try:
            gid = grp.getgrnam(str(vol['group'])).gr_gid
        except KeyError:
            host.module.fail_json(msg="%s.volume.%s: no such group %s" % (what, name, vol['group']))
    if (uid, gid) != (st.st_uid, st.st_gid):
        host.plan.append("chown %s:%s %s" % (uid, gid, name))
        if not host.check:
            os.chown(path, uid, gid)
    if 'mode' in vol:
        mode = int(str(vol['mode']), 8)
        if stat.S_IMODE(st.st_mode) != mode:
            host.plan.append("chmod %o %s" % (mode, name))
            if not host.check:
                os.chmod(path, mode)


def _emit_mounts(host, label, real, kind, fs_options, volumes):
    for name, vol in volumes.items():
        try:
            options = options_of(vol, 'btrfs.%s.volume.%s' % (label, name))
        except ValueError as e:
            host.module.fail_json(msg=str(e))
        opts = list(fs_options) + options + ['subvol=/%s' % name]
        if kind == 'file':
            opts.append('loop')
        host.mounts.append({'path': vol['mount'], 'src': fstab_source(kind, real, label),
                            'fstype': 'btrfs', 'opts': ','.join(opts)})


def apply_swap(host, label, spec):
    what = 'swap.%s' % label
    device = spec.get('device')
    if not isinstance(device, str) or not device.startswith('/'):
        host.module.fail_json(msg="%s: device must be an absolute path" % what)
    real = os.path.realpath(device)
    if not os.path.exists(real):
        if 'size' not in spec:
            host.module.fail_json(msg="%s: device %s does not exist and size is not given" % (what, device))
        try:
            size = to_bytes(spec['size'], what)
        except ValueError as e:
            host.module.fail_json(msg=str(e))
        host.plan.append("create %s of %s" % (real, spec['size']))
        if host.check:
            host.plan.append("mkswap %s on %s" % (label, real))
            host.mounts.append({'path': 'none', 'src': fstab_source('file', real, label), 'fstype': 'swap', 'opts': 'sw'})
            return
        parent = os.path.dirname(real)
        if not os.path.isdir(parent):
            os.makedirs(parent, 0o755)
        fd = os.open(real, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        if host.run(['stat', '-f', '-c', '%T', parent]).strip() == 'btrfs':
            host.run(['chattr', '+C', real])
        host.run(['fallocate', '-l', str(size), real])
    kind, real = device_kind(host, what, real)
    if kind == 'absent':
        host.plan.append("mkswap %s on %s once wyga/storage made it" % (label, device))
        host.mounts.append({'path': 'none', 'src': fstab_source('block', real, label), 'fstype': 'swap', 'opts': 'sw'})
        return
    sig = blkid(host, real)
    if not sig.get('TYPE'):
        host.act("mkswap %s on %s" % (label, real), ['mkswap', '-q', '-L', label, real])
    elif sig['TYPE'] != 'swap':
        host.module.fail_json(msg="%s: %s holds %s, refusing to touch it" % (what, device, sig['TYPE']))
    elif sig.get('LABEL') != label:
        host.act("label %s as %s" % (real, label), ['swaplabel', '-L', label, real])
    active = set()
    with open('/proc/swaps') as f:
        for line in f.readlines()[1:]:
            active.add(line.split()[0])
    if real not in active:
        host.act("swapon %s" % real, ['swapon', real])
    host.mounts.append({'path': 'none', 'src': fstab_source(kind, real, label), 'fstype': 'swap', 'opts': 'sw'})


def main():
    module = AnsibleModule(
        argument_spec=dict(
            btrfs=dict(type='dict', default={}),
            swap=dict(type='dict', default={}),
        ),
        supports_check_mode=True,
    )
    host = Host(module)
    btrfs = module.params['btrfs'] or {}
    swap = module.params['swap'] or {}
    for section, entries in (('btrfs', btrfs), ('swap', swap)):
        for label, spec in entries.items():
            if not _LABEL.match(str(label)):
                module.fail_json(msg="%s.%s: not a valid label" % (section, label))
            if not isinstance(spec, dict):
                module.fail_json(msg="%s.%s must be a map" % (section, label))
    if btrfs:
        for tool in ('mkfs.btrfs', 'btrfs', 'blkid', 'findmnt', 'losetup'):
            if not module.get_bin_path(tool):
                module.fail_json(msg="%s not found: btrfs-progs is required for btrfs" % tool)
    for label in sorted(btrfs):
        apply_btrfs(host, str(label), btrfs[label])
    for label in sorted(swap):
        apply_swap(host, str(label), swap[label])
    module.exit_json(changed=bool(host.plan), plan=host.plan, mounts=host.mounts,
                     diff={'prepared': '\n'.join(host.plan) + '\n' if host.plan else ''})


if __name__ == '__main__':
    main()
