from ansible.errors import  AnsibleFilterError
from ansible.module_utils.six import string_types
from ansible.module_utils.common.collections import is_sequence

def parse_package(packages, target_distribution='target',  target_arch='target'):
  if isinstance(packages, string_types):
    packages = [ packages ]
  if not is_sequence(packages):
    raise AnsibleFilterError("filter requires a list, got %s instead." % type(packages))
  result = []

  for package in packages:
    entry = {}
    package = package.lower()
    entry['include'] = package.startswith('.')
    package = package.lstrip('.')
    entry['op'] = 'add'
    if package.startswith('-'):
      entry['op'] = 'purge'
      package = package.lstrip('-')
    elif package.startswith('+'):
      package = package.lstrip('+')

    package = package.lstrip('.')
    if '@' in package:
      name, remainder = package.split('@', 1)
      entry['name'] = name
      if '/' in remainder:
        distribution, arch = remainder.split('/', 1)
        entry['arch'] = arch
      else:
        distribution = remainder
      if ':' in distribution:
        distribution, version = distribution.split(':', 1)
        entry['version'] = version
      entry['distribution'] = distribution
    else:
      name = package
      if '/' in package:
        name, arch = package.split('/', 1)
        entry['arch'] = arch
      entry['name'] = name

    if 'distribution' not in entry and target_distribution.strip():
      entry['distribution'] = target_distribution
    if 'arch' not in entry and target_arch.strip():
      entry['arch'] = target_arch
    if 'version' not in entry:
      entry['version'] = 'target'
    result.append(entry)

  return result

class FilterModule(object):
  def filters(self):
    return {
      'parsepackage': parse_package,
    }
