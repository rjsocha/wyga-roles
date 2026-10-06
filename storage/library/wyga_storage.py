#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = """
---
module: wyga_storage
short_description: Block devices of a host as the policy declares them.
description:
  - lvm.vg - every volume group named must exist. One with 'device'
    is made from those devices when it does not exist (GPT with one
    partition of type LVM, pvcreate, vgcreate); a device not yet in the
    group extends it. A device with any signature or partition table is
    never touched.
  - lvm.lv - a logical volume is created in its group with 'size' and
    grown when 'size' is larger; it is never shrunk or removed.
  - loop - a sparse file of 'size' is created and grown; never shrunk.
  - Check mode reports the plan without running it.
options:
  lvm:
    description: "{vg: {name: {device: [path]}}, lv: {name: {vg: name, size: str}}}"
    type: dict
  loop:
    description: "{name: {file: path, size: str}}"
    type: dict
"""

RETURN = """
plan:
  description: The actions taken, or to take in check mode.
  returned: always
  type: list
"""

import json
import os
import re
import time

from ansible.module_utils.basic import AnsibleModule

LVM_PART_TYPE = 'E6D6D379-F507-44C2-A23C-238F2A3DF928'
_UNITS = {'': 1, 'B': 1, 'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30, 'T': 1 << 40, 'P': 1 << 50}
_NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.+-]*$')


def to_bytes(size, what):
    """A size as lvm reads it: a number with K, M, G, T, P (binary), with
    an optional B or iB."""
    m = re.match(r'^\s*(\d+(?:\.\d+)?)\s*([KMGTP]?)(?:I?B)?\s*$', str(size), re.I)
    if not m:
        raise ValueError("%s: size %r is not a number with a unit of K, M, G, T or P" % (what, size))
    return int(float(m.group(1)) * _UNITS[m.group(2).upper()])


class Host(object):
    """The commands on the host; every call fails the module on error."""

    def __init__(self, module):
        self.module = module
        self.check = module.check_mode
        self.plan = []

    def run(self, args, **kw):
        rc, out, err = self.module.run_command(args, **kw)
        if rc != 0:
            self.module.fail_json(msg="%s: %s" % (' '.join(args), (err or out).strip()))
        return out

    def act(self, what, args):
        self.plan.append(what)
        if not self.check:
            self.run(args)

    def report(self, args):
        out = self.run(args)
        return json.loads(out)['report'][0] if out.strip() else {}


def lvm_state(host):
    report = host.report(['pvs', '--reportformat', 'json', '--units', 'b', '--nosuffix',
                          '-o', 'pv_name,vg_name'])
    pvs = {pv['pv_name']: pv['vg_name'] for pv in report.get('pv', [])}
    report = host.report(['vgs', '--reportformat', 'json', '-o', 'vg_name'])
    vgs = {vg['vg_name'] for vg in report.get('vg', [])}
    report = host.report(['lvs', '--reportformat', 'json', '--units', 'b', '--nosuffix',
                          '-o', 'vg_name,lv_name,lv_size'])
    lvs = {(lv['vg_name'], lv['lv_name']): int(lv['lv_size']) for lv in report.get('lv', [])}
    return pvs, vgs, lvs


def block_device(host, path):
    """lsblk of one device: its path, type, signatures and children."""
    out = host.run(['lsblk', '-J', '--tree', '-o', 'PATH,TYPE,FSTYPE,PTTYPE,PARTTYPE', path])
    return json.loads(out)['blockdevices'][0]


def lvm_partition(dev):
    """The one partition of the device when it is an LVM partition with
    no other partition beside it: the physical volume, made or to make."""
    parts = [c for c in dev.get('children') or [] if c['type'] == 'part']
    if len(parts) == 1 and (parts[0].get('fstype') == 'LVM2_member'
                            or (parts[0].get('parttype') or '').upper() == LVM_PART_TYPE):
        return parts[0]['path']
    return None


def prepare_pv(host, vg, device):
    """A fresh device becomes one LVM partition; the partition path, or
    the existing physical volume of the group."""
    real = os.path.realpath(device)
    if not os.path.exists(real):
        host.module.fail_json(msg="lvm.vg.%s: device %s does not exist" % (vg, device))
    dev = block_device(host, real)
    part = lvm_partition(dev)
    if part:
        return part
    if dev.get('fstype') == 'LVM2_member':
        return dev['path']
    if dev.get('fstype') or dev.get('pttype') or dev.get('children'):
        host.module.fail_json(msg="lvm.vg.%s: device %s holds %s, refusing to touch it"
                              % (vg, device, dev.get('fstype') or dev.get('pttype') or 'partitions'))
    if dev['type'] != 'disk':
        host.module.fail_json(msg="lvm.vg.%s: device %s is a %s, want a disk" % (vg, device, dev['type']))
    host.plan.append("partition %s for lvm" % real)
    if host.check:
        return real + '-part1'
    host.run(['sfdisk', '--quiet', '--label', 'gpt', real], data='type=%s\n' % LVM_PART_TYPE)
    for _ in range(50):
        host.run(['udevadm', 'settle'])
        part = lvm_partition(block_device(host, real))
        if part and os.path.exists(part):
            return part
        time.sleep(0.2)
    host.module.fail_json(msg="lvm.vg.%s: %s: the partition did not appear after sfdisk" % (vg, device))


def apply_vg(host, name, spec, pvs, vgs):
    devices = spec.get('device') or []
    if isinstance(devices, str):
        devices = [devices]
    if name not in vgs and not devices:
        host.module.fail_json(msg="lvm.vg.%s: volume group does not exist on this host" % name)
    if not devices:
        return
    wanted = []
    for device in devices:
        pv = prepare_pv(host, name, device)
        real = os.path.realpath(pv)
        owner = pvs.get(real) or None
        if owner and owner != name:
            host.module.fail_json(msg="lvm.vg.%s: %s belongs to volume group %s" % (name, device, owner))
        if owner is None:
            host.act("pvcreate %s" % real, ['pvcreate', '--quiet', '--yes', real])
            wanted.append(real)
        elif name not in vgs:
            wanted.append(real)
    if name not in vgs:
        host.act("vgcreate %s %s" % (name, ' '.join(wanted)), ['vgcreate', '--quiet', '--yes', name] + wanted)
        vgs.add(name)
    elif wanted:
        host.act("vgextend %s %s" % (name, ' '.join(wanted)), ['vgextend', '--quiet', '--yes', name] + wanted)


def apply_lv(host, name, spec, vgs, lvs):
    vg = spec.get('vg')
    if not isinstance(vg, str) or vg not in vgs:
        host.module.fail_json(msg="lvm.lv.%s: vg must name a volume group declared in lvm.vg" % name)
    if 'size' not in spec:
        host.module.fail_json(msg="lvm.lv.%s: size is required" % name)
    try:
        size = to_bytes(spec['size'], 'lvm.lv.%s' % name)
    except ValueError as e:
        host.module.fail_json(msg=str(e))
    current = lvs.get((vg, name))
    if current is None:
        host.act("lvcreate %s/%s %s" % (vg, name, spec['size']),
                 ['lvcreate', '--quiet', '--yes', '--wipesignatures', 'y', '--zero', 'y',
                  '-n', name, '-L', '%dB' % size, vg])
    elif size > current:
        host.act("lvextend %s/%s to %s" % (vg, name, spec['size']),
                 ['lvextend', '--quiet', '-L', '%dB' % size, '/dev/%s/%s' % (vg, name)])


def apply_loop(host, name, spec):
    path = spec.get('file')
    if not isinstance(path, str) or not path.startswith('/'):
        host.module.fail_json(msg="loop.%s: file must be an absolute path" % name)
    if 'size' not in spec:
        host.module.fail_json(msg="loop.%s: size is required" % name)
    try:
        size = to_bytes(spec['size'], 'loop.%s' % name)
    except ValueError as e:
        host.module.fail_json(msg=str(e))
    if os.path.lexists(path):
        st = os.lstat(path)
        if not os.path.isfile(path) or os.path.islink(path):
            host.module.fail_json(msg="loop.%s: %s is not a regular file" % (name, path))
        if size > st.st_size:
            host.plan.append("grow %s to %s" % (path, spec['size']))
            if not host.check:
                os.truncate(path, size)
        return
    host.plan.append("create %s of %s" % (path, spec['size']))
    if host.check:
        return
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent, 0o755)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.ftruncate(fd, size)
    finally:
        os.close(fd)


def check_names(module, section, entries):
    if not isinstance(entries, dict):
        module.fail_json(msg="%s must be a map" % section)
    for name, spec in entries.items():
        if not _NAME.match(str(name)):
            module.fail_json(msg="%s.%s: not a valid name" % (section, name))
        if spec is not None and not isinstance(spec, dict):
            module.fail_json(msg="%s.%s must be a map" % (section, name))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            lvm=dict(type='dict', default={}),
            loop=dict(type='dict', default={}),
        ),
        supports_check_mode=True,
    )
    lvm = module.params['lvm'] or {}
    loop = module.params['loop'] or {}
    vg_spec = lvm.get('vg') or {}
    lv_spec = lvm.get('lv') or {}
    check_names(module, 'lvm.vg', vg_spec)
    check_names(module, 'lvm.lv', lv_spec)
    check_names(module, 'loop', loop)
    for key in lvm:
        if key not in ('vg', 'lv'):
            module.fail_json(msg="lvm.%s: unknown key, want vg or lv" % key)

    host = Host(module)
    if vg_spec or lv_spec:
        for tool in ('pvs', 'vgs', 'lvs', 'lvcreate', 'sfdisk', 'lsblk'):
            if not module.get_bin_path(tool):
                module.fail_json(msg="%s not found: lvm2 is required for lvm" % tool)
        pvs, vgs, lvs = lvm_state(host)
        for name in sorted(vg_spec):
            apply_vg(host, name, vg_spec[name] or {}, pvs, vgs)
        for name in sorted(lv_spec):
            apply_lv(host, name, lv_spec[name] or {}, vgs, lvs)
    for name in sorted(loop):
        apply_loop(host, name, loop[name] or {})

    module.exit_json(changed=bool(host.plan), plan=host.plan,
                     diff={'prepared': '\n'.join(host.plan) + '\n' if host.plan else ''})


if __name__ == '__main__':
    main()
