import os
import re

from ansible import constants as C
from ansible.inventory.manager import InventoryManager
from ansible.plugins.inventory import BaseInventoryPlugin

DOCUMENTATION = '''
name: local-policy
short_description: A policy file as inventory source
description:
  - A file in the policy directory next to ansible.cfg becomes a host
    named after the file, without the .yaml or .yml extension.
  - The groups and variables of that host come from the hosts file next
    to ansible.cfg, when the host is listed there.
'''

BASE = os.path.dirname(os.path.abspath(C.CONFIG_FILE or 'ansible.cfg'))
SKIP_GROUPS = ('all', 'ungrouped')
SKIP_VARS = ('inventory_file', 'inventory_dir')


class InventoryModule(BaseInventoryPlugin):
    NAME = 'local-policy'

    def verify_file(self, path):
        policy = os.path.join(BASE, 'policy')
        return (os.path.isfile(path)
                and os.path.realpath(os.path.dirname(path)) == os.path.realpath(policy))

    def parse(self, inventory, loader, path, cache=True):
        super().parse(inventory, loader, path, cache)
        name = re.sub(r'\.ya?ml$', '', os.path.basename(path))
        self.inventory.add_host(name)
        hosts = os.path.realpath(os.path.join(BASE, 'hosts'))
        if not os.path.isfile(hosts):
            return
        known = InventoryManager(loader=loader, sources=[hosts]).get_host(name)
        if known is None:
            return
        for group in known.get_groups():
            if group.name in SKIP_GROUPS:
                continue
            self.inventory.add_group(group.name)
            self.inventory.add_child(group.name, name)
        for key, value in known.vars.items():
            if key not in SKIP_VARS:
                self.inventory.set_variable(name, key, value)
