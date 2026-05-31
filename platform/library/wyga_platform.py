#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = """
---
module: wyga_platform
short_description: Build the target facts dict for a host.
description:
  - Detects firmware mode (uefi/bios) from /sys/firmware/efi.
  - Discovers physical boot devices (findmnt + lsblk -s) when
    devices=['auto'], otherwise passes the provided list through.
  - Normalizes arch (x86_64 -> amd64, aarch64 -> arm64).
  - Validates distribution+version against the supported matrix; fails
    on unsupported combinations. This makes the module the single
    gate for "is this host supported" — other roles can trust 'platform'.
  - Currently supported - debian 12/13, ubuntu 22.04/24.04/26.04,
    on x86_64/aarch64.
  - Returns a complete 'platform' fact via ansible_facts.
options:
  devices:
    description:
      - ['auto'] triggers detection; explicit list bypasses detection.
    type: list
    elements: str
    required: true
  distribution:
    description: Distribution name (lowercase).
    type: str
    required: true
  version:
    description:
      - Distribution version as reported by ansible
        (e.g. '13.1' for Debian, '24.04' for Ubuntu).
      - Normalized internally per distribution
        (debian -> major only, ubuntu -> major.minor).
    type: str
    required: true
  arch:
    description: Architecture as reported by ansible (e.g. 'x86_64', 'aarch64').
    type: str
    required: true
"""

RETURN = """
ansible_facts:
  description: Sets the 'platform' fact globally.
  returned: always
  type: dict
  contains:
    platform:
      description: Complete platform description.
      type: dict
      sample:
        firmware: bios
        arch:
          machine: x86_64
          package: amd64
        distribution: debian
        version: '13'
        boot:
          devices: ['/dev/vda']
        initramfs:
          tool: initramfs-tools
"""

import os
import re
import subprocess

from ansible.module_utils.basic import AnsibleModule

_SUPPORTED = {
    'debian': ['12', '13'],
    'ubuntu': ['22.04', '24.04', '26.04'],
}

_ARCH_MAP = {
    'x86_64':  'amd64',
    'aarch64': 'arm64',
}


# How many leading dot-separated segments to keep from ansible_distribution_version.
# debian: 1 (major only — '13.1' -> '13'); ubuntu: 2 ('22.04.4' -> '22.04').
_VERSION_GRANULARITY = {
    'debian': 1,
    'ubuntu': 2,
}


def _normalize_version(distribution, version):
    n = _VERSION_GRANULARITY.get(distribution)
    if n is None:
        return version
    return '.'.join(version.split('.')[:n])


def detect_firmware():
    return 'uefi' if os.path.isdir('/sys/firmware/efi') else 'bios'


def detect_initramfs_tool():
    # initramfs-tools and dracut conflict in deb metadata — only one is
    # ever installed at a time. /usr/bin/dracut is the dracut binary
    # (not the update-initramfs shim that dracut also provides for compat).
    if os.path.isfile('/usr/bin/dracut'):
        return 'dracut'
    if os.path.isfile('/usr/sbin/update-initramfs'):
        return 'initramfs-tools'
    return 'none'


def detect_boot_devices(module):
    try:
        root_source = subprocess.run(
            ['findmnt', '-no', 'SOURCE', '/'],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except FileNotFoundError:
        module.fail_json(msg="findmnt not found in PATH")
    except subprocess.CalledProcessError as e:
        module.fail_json(msg=f"findmnt failed: {e.stderr.strip()}")

    if not root_source:
        module.fail_json(msg="findmnt returned no source for /")

    # findmnt may append [/subvol] for btrfs subvolumes; strip it.
    root_source = re.sub(r'\[.*\]$', '', root_source).strip()

    try:
        lsblk_out = subprocess.run(
            ['lsblk', '-snlpo', 'NAME,TYPE', root_source],
            capture_output=True, text=True, check=True,
        ).stdout
    except FileNotFoundError:
        module.fail_json(msg="lsblk not found in PATH")
    except subprocess.CalledProcessError as e:
        module.fail_json(msg=f"lsblk failed for {root_source!r}: {e.stderr.strip()}")

    disks = []
    for line in lsblk_out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == 'disk':
            if parts[0] not in disks:
                disks.append(parts[0])

    if not disks:
        module.fail_json(msg=f"no physical disks found in tree below {root_source!r}")

    return sorted(disks)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            devices=dict(type='list', elements='str', required=True),
            distribution=dict(type='str', required=True),
            version=dict(type='str', required=True),
            arch=dict(type='str', required=True),
        ),
        supports_check_mode=True,
    )

    distribution = module.params['distribution']
    version_raw = module.params['version']
    arch_raw = module.params['arch']

    if distribution not in _SUPPORTED:
        module.fail_json(
            msg=f"unsupported distribution {distribution!r}; "
            f"supported: {sorted(_SUPPORTED.keys())}"
        )
    version = _normalize_version(distribution, version_raw)
    if version not in _SUPPORTED[distribution]:
        module.fail_json(
            msg=f"unsupported version {version_raw!r} (normalized {version!r}) "
            f"for {distribution!r}; supported: {_SUPPORTED[distribution]}"
        )
    if arch_raw not in _ARCH_MAP:
        module.fail_json(
            msg=f"unsupported architecture {arch_raw!r}; "
            f"supported: {sorted(_ARCH_MAP.keys())}"
        )

    devices_arg = module.params['devices']
    if not devices_arg:
        module.fail_json(msg="devices must not be empty (use ['auto'] for detection)")

    if devices_arg == ['auto']:
        boot_devices = detect_boot_devices(module)
    else:
        boot_devices = list(devices_arg)

    platform = dict(
        firmware=detect_firmware(),
        arch=dict(
            machine=arch_raw,
            package=_ARCH_MAP[arch_raw],
        ),
        distribution=distribution,
        version=version,
        boot=dict(devices=boot_devices),
        initramfs=dict(tool=detect_initramfs_tool()),
    )

    module.exit_json(changed=False, ansible_facts=dict(platform=platform))


if __name__ == '__main__':
    main()
