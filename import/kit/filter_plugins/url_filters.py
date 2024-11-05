from ansible.errors import  AnsibleFilterError
from ansible.module_utils.six import string_types
from ansible.module_utils.common.collections import is_sequence
from urllib.parse import urlparse

def is_wildcard(domain):
  return '*' in domain

def is_wildcard_correct(domain):
  if is_wildcard(domain):
    parts = domain.split('.',1)
    if len(parts) > 1:
      rest = parts[1]
      if not is_wildcard(rest):
        return True
  return False

# Returns list of wildcard domain names from list of urls
def kit_wildcard_domains(mylist):
  if not is_sequence(mylist):
    raise AnsibleFilterError("filter requires a list, got %s instead." % type(mylist))
  wildcards = set()
  for domain in mylist:
    if not isinstance(domain, string_types):
      raise AnsibleFilterError("list element must be strings, got %s instead." % type(domain))
    url = urlparse(domain)
    host = url.hostname if url.hostname else domain
    if not is_wildcard(host):
      continue
    if is_wildcard_correct(host):
      wildcards.add(host.split('.',1)[1])
    else:
      raise AnsibleFilterError("unsupporeted wildcard url %s." % domain)
  return list(wildcards)

def wyga_san_normalize(domain,wildcards):
  if not isinstance(domain, string_types):
     raise AnsibleFilterError("first parameter must be string, got %s instead." % type(domain))
  if not is_sequence(wildcards):
    raise AnsibleFilterError("filter requires a list, got %s instead." % type(wildcards))
  if len(domain.split('.',1)) > 1:
    ends = domain.split('.',1)[1]
    for matcher in wildcards:
      if ends == matcher:
        return matcher
  return domain

class FilterModule(object):
  def filters(self):
    return {
      'kit_wildcard_domains': kit_wildcard_domains,
      'wyga_san_normalize': wyga_san_normalize,
    }
