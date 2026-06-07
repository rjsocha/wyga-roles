import hashlib
from ansible.errors import  AnsibleFilterError
from ansible.module_utils.six import string_types
from ansible.module_utils.common.collections import is_sequence
from urllib.parse import urlsplit

def is_wildcard(domain):
  if '*' in domain:
    parts = domain.split('.',1)
    if len(parts) > 1:
      rest = parts[1]
      if '*' not in rest:
        return True
  return False

def wildcard_domains(domains):
  wildcards = set()
  for domain in domains:
    url = urlsplit(domain)
    host = url.hostname if url.hostname else domain
    if is_wildcard(host):
      wildcards.add( host.split('.',1)[1] )
  return list(wildcards)

def wildcarded(domain,wildcards):
  if len(domain.split('.',1)) > 1:
    ends = domain.split('.',1)[1]
    for matcher in wildcards:
      if ends == matcher:
        return matcher
  return domain

def host2rx(host, de=False):
  host = host.replace(".","\\\\.") if de else host.replace(".","\\.")
  host = host.replace("*","[a-z0-9][a-z0-9-]{0,61}[a-z0-9]?")
  return host

def add_rule(rule, url, entry_count):
  host = urlsplit(url).hostname
  if '*' in host:
    if not is_wildcard(host):
      raise AnsibleFilterError("Malformed url %s (%s) ..." % (url, entry_count))
    host = host2rx(host)
    host = f"(?i)^{host}$"
    rule = f"{rule} || HostRegexp(`{host}`)" if rule else f"HostRegexp(`{host}`)"
  else:
    rule = f"{rule} || Host(`{host}`)" if rule else f"Host(`{host}`)"
  return rule

def noduplicates(lst):
  seen = set()
  result = []
  for item in lst:
    if item not in seen:
      seen.add(item)
      result.append(item)
  return result

def normalize_redirect(value):
  if value is None:
    return None
  if isinstance(value, string_types):
    parts = value.split(":", 1)
    to = parts[0]
    priority = None
    if len(parts) > 1 and parts[1] != "":
      try:
        priority = int(parts[1])
      except ValueError:
        raise AnsibleFilterError("redirect priority '%s' is not an integer ..." % parts[1])
  elif isinstance(value, dict):
    if "to" not in value:
      raise AnsibleFilterError("redirect missing 'to' key ...")
    to = value["to"]
    priority = value.get("priority")
  else:
    raise AnsibleFilterError("redirect must be string or dict, got %s instead ..." % type(value))
  return { "to": to, "priority": priority }

def normalize_entrypoints(ingress):
  defaults = {
    "http":  { "type": "http",  "address": "", "port": 80,  "default": False, "http3": True, "redirect": { "to": "https", "priority": 1 } },
    "https": { "type": "https", "address": "", "port": 443, "default": True,  "http3": True, "redirect": None },
  }
  entrypoints = ingress.get("entrypoint")
  if not entrypoints:
    ingress["entrypoint"] = defaults
    return
  if not isinstance(entrypoints, dict):
    raise AnsibleFilterError("entrypoint must be a dict, got %s instead ..." % type(entrypoints))
  normalized = {}
  for name, spec in entrypoints.items():
    if spec == "default":
      if name not in defaults:
        raise AnsibleFilterError("entrypoint '%s' has no built-in 'default', only http/https do ..." % name)
      normalized[name] = dict(defaults[name])
      continue
    spec = spec or {}
    if not isinstance(spec, dict):
      raise AnsibleFilterError("entrypoint '%s' must be a dict or 'default', got %s instead ..." % (name, type(spec)))
    etype = spec.get("type")
    if etype not in ( "http", "https" ):
      raise AnsibleFilterError("entrypoint '%s' has invalid type '%s', must be 'http' or 'https' ..." % (name, etype))
    normalized[name] = {
      "type": etype,
      "address": spec.get("address", spec.get("bind", "")),
      "port": spec.get("port", 80 if etype == "http" else 443),
      "default": spec.get("default", False),
      "http3": spec.get("http3", True),
      "redirect": normalize_redirect(spec.get("redirect")),
    }
  for name, ep in normalized.items():
    if ep["redirect"] and ep["redirect"]["to"] not in normalized:
      raise AnsibleFilterError("entrypoint '%s' redirect target '%s' is not a defined entrypoint ..." % (name, ep["redirect"]["to"]))
  ingress["entrypoint"] = normalized

def resolve_cert_path(path, store):
  if path.startswith("/"):
    return path
  if not store:
    raise AnsibleFilterError("relative certificate '%s' requires tls.store to be set ..." % path)
  return "%s/%s.pem" % (store.rstrip("/"), path)

def normalize_certificates(ingress):
  tls = ingress.get("tls")
  if not tls:
    return
  certs = tls.get("certificates")
  if not certs:
    return
  provider = ingress.get("provider") or {}
  if "file" not in provider:
    raise AnsibleFilterError("tls.certificates requires the file provider (provider.file) to be enabled ...")
  store = tls.get("store")
  resolved = []
  for entry in certs:
    if isinstance(entry, string_types):
      cert = key = entry
    elif isinstance(entry, dict):
      cert = entry.get("cert")
      if not cert:
        raise AnsibleFilterError("certificate entry missing 'cert' key ...")
      key = entry.get("key", cert)
    else:
      raise AnsibleFilterError("certificate entry must be string or dict, got %s instead ..." % type(entry))
    resolved.append({ "certFile": resolve_cert_path(cert, store), "keyFile": resolve_cert_path(key, store) })
  tls["certificates"] = resolved

def expand_redirects(ingress):
  redirects = ingress.pop("redirect", None)
  if not redirects:
    return
  if not isinstance(redirects, list):
    raise AnsibleFilterError("redirect must be a list, got %s instead ..." % type(redirects))
  vhosts = ingress.setdefault("vhost", [])
  for entry in redirects:
    if not isinstance(entry, dict):
      raise AnsibleFilterError("redirect entry must be a dict, got %s instead ..." % type(entry))
    to = entry.get("to")
    if not to:
      raise AnsibleFilterError("redirect entry missing 'to' key ...")
    if "://" not in to:
      to = "https://" + to
    frm = entry.get("from")
    if not frm:
      raise AnsibleFilterError("redirect entry missing 'from' key ...")
    sources = [ frm ] if isinstance(frm, string_types) else list(frm)
    urls = []
    for src in sources:
      scheme = urlsplit(src).scheme
      if scheme in ( "", "http2s" ):
        host = urlsplit(src).hostname or src
        urls.append("http://" + host)
        urls.append("https://" + host)
      else:
        urls.append(src)
    vhosts.append({ "to": to, "config": { "url": urls } })

def process_ingress_config(ingress):
  normalize_entrypoints(ingress)
  normalize_certificates(ingress)
  expand_redirects(ingress)
  runtime_files = [ "config.yaml" ]
  tls_domains = set()

  acme_files = {
    "acme.dns.%s.json" % entry.get("provider") for entry in ingress.get("acme", {}).get("dns", [])
  }

  providers = {
    entry.get("name") or entry.get("provider") for entry in ingress.get("acme", {}).get("dns", [])
  }
  providers.add("none")

  acme_http = ingress.get("acme",{}).get("http",False)
  if acme_http:
    providers.add("http")
    acme_files.add("acme.http.json")

  ingress.setdefault("acme", {})
  ingress["acme"]["files"] = list(acme_files)

  dashboard = ingress.get("dashboard", {})
  dashboard_url = dashboard.get("url")
  if dashboard_url:
    dashboard_ep = dashboard.get("entrypoint", dashboard.get("via"))
    if dashboard_ep is not None:
      if dashboard_ep not in ingress["entrypoint"]:
        raise AnsibleFilterError("dashboard entrypoint '%s' is not defined ..." % dashboard_ep)
      dashboard["entrypoint"] = dashboard_ep
      dashboard_tls = ingress["entrypoint"][dashboard_ep]["type"] == "https"
    else:
      dashboard_tls = urlsplit(dashboard_url).scheme in [ 'https', 'http2s' ]
    if dashboard_tls:
      tls_domains.add(urlsplit(dashboard_url).hostname)

  if 'vhost' not in ingress:
    ingress["files"] = runtime_files
    ingress["tls_domains"] = list(tls_domains)
    return ingress

  vhosts = ingress.get("vhost", [])

  config  = []
  seen_san = set()
  seen_url = set()
  seen_redirect = set()
  chains = {}
  wildcard_provider = {}
  entry_count = 0
  for vhost in vhosts:
    entry_count = entry_count + 1
    redirect_target = set()
    if not 'config' in vhost:
      raise AnsibleFilterError("'config' key not present (%s) ..." % entry_count)

    cfg = vhost["config"]

    runtime = {}

    has_upstream = 'upstream' in cfg
    has_backend  = 'backend' in cfg

    if has_upstream and has_backend:
      raise AnsibleFilterError("Both 'upstream' and 'backend' are defined; only one must be used (%s) ..." % entry_count)

    if has_upstream or has_backend:
      backend = cfg['upstream'] if has_upstream else cfg['backend']
      if isinstance(backend, str):
        if not urlsplit(backend).scheme in [ "http", "https" ]:
          raise AnsibleFilterError("Neither http:// nor https:// scheme is set for the backend: %s (%s) ..." % (backend, entry_count))
        backend = { 'servers': [ { 'url': backend } ] }
      elif isinstance(backend, dict):
        if 'servers' not in backend:
          raise AnsibleFilterError("missing servers key for backend (%s) ..." % (entry_count))
        if not isinstance(backend['servers'], list):
          raise AnsibleFilterError("backend servers should be a list, got %s instead (%s) ..." % (type(backend['servers']), entry_count))
        for srv in backend['servers']:
          if 'url' not in srv:
            raise AnsibleFilterError("missing url for backend servers (%s) ..." % (entry_count))
          if not urlsplit(srv['url']).scheme in [ "http", "https" ]:
            raise AnsibleFilterError("Neither http:// nor https:// scheme is set for the backend: %s (%s) ..." % (srv.url, entry_count))
      else:
        raise AnsibleFilterError("backend must be string or dictonary, got %s instead (%s) ..." % (type(backend), entry_count))
      runtime["backend"] = backend
      redirect = False
    elif 'url' in cfg:
      runtime["backend"] = "noop@internal"
      redirect = True
    else:
      raise AnsibleFilterError("Neither a backend nor a redirect is defined (%s) ..." % entry_count)

    san = cfg.get("san", [])
    sans = []
    if isinstance(san, string_types):
      sans.append(san)
    elif is_sequence(san):
      sans.extend(san)
    else:
      raise AnsibleFilterError("san must be string or list, got %s instead (%s) ..." % (type(san), entry_count))
    sans_empty = not sans

    # redirect only mode
    if redirect:
      if not 'to' in vhost:
        raise AnsibleFilterError("'to' key not present for redirect (%s) ..." % entry_count)
      to = vhost["to"]
      if not isinstance(to, string_types):
        raise AnsibleFilterError("'to' must be string, got %s instead (%s) ..." % (type(url), entry_count))
      if not urlsplit(to).scheme in [ "http", "https" ]:
        raise AnsibleFilterError("Neither http:// nor https:// scheme is set for redirect target: %s ..." % to)
      idx=0
      while True:
        idx += 1
        redirect_file =  "redir-%s-%s.yaml" % (urlsplit(to).hostname,idx)
        if redirect_file in runtime_files:
          continue
        runtime["file"] = redirect_file
        break
      runtime["id"] = hashlib.md5(redirect_file.encode("utf-8")).hexdigest()[:12]

      if 'url' not in cfg:
        raise AnsibleFilterError("'url' key not present for redirect entry %s (%s) ..." % (to,entry_count))

      url = cfg["url"]
      urls = []
      if isinstance(url, string_types):
        urls.append(url)
      elif is_sequence(url):
        urls.extend(url)
      else:
        raise AnsibleFilterError("url must be string or list, got %s instead (%s) ..." % (type(url), entry_count))
      for url in urls:
        if url in seen_url:
          raise AnsibleFilterError("url already defined %s (%s) ..." % (url, entry_count))
        seen_url.add(url)
      runtime["url"] = urls
    else:
      if 'url' not in vhost:
        raise AnsibleFilterError("'url' key not present (%s) ..." % entry_count)
      url = vhost["url"]
      urls = []
      if isinstance(url, string_types):
        urls.append(url)
      elif is_sequence(url):
        urls.extend(url)
      else:
        raise AnsibleFilterError("url must be string or list, got %s instead (%s) ..." % (type(url), entry_count))
      for url in urls:
        if url in seen_url:
          raise AnsibleFilterError("url already defined %s (%s) ..." % (url, entry_count))
        seen_url.add(url)
      runtime["url"] = urls
      url = urls[0]
      runtime["id"] = hashlib.md5(url.encode("utf-8")).hexdigest()[:12]
      runtime["file"] = "vhost-" + urlsplit(url).hostname + ".yaml"

    runtime_files.append(runtime["file"])

    tls = cfg.get("tls")
    if tls:
      if tls not in providers:
        raise AnsibleFilterError("TLS provider '%s' used in %s is not defined (%s) ..." % (tls, urls[0], entry_count))
      runtime["tls"] = tls
    else:
      if "http" in providers:
        runtime["tls"] = "http"
      else:
        runtime["tls"] = "none"
    tls = runtime["tls"]

    rule_http = str()
    rule_https = str()
    http = https = http2s = False
    seen_http = set()
    seen_https = set()
    for url in urls:
      host = urlsplit(url).hostname
      scheme = urlsplit(url).scheme
      if not scheme in [ 'http','https','http2s' ]:
          raise AnsibleFilterError("Unsupported url %s (%s) ..." % (url, entry_count))
      if 'redirect' not in cfg:
        cfg['redirect'] = []
      if scheme == "http2s":
        http = https = True
        cfg['redirect'].append("http2s://" + host)
        tls_domains.add(host)
        if sans_empty:
          sans.append(host)
        if host not in seen_http:
          seen_http.add(host)
          rule_http = add_rule(rule_http, url, entry_count)
        if host not in seen_https:
          seen_https.add(host)
          rule_https = add_rule(rule_https, url, entry_count)
      if scheme == "https":
        https = True
        if redirect:
          cfg['redirect'].append("https://" + host)
        tls_domains.add(host)
        if sans_empty:
          sans.append(host)
        if host not in seen_https:
          seen_https.add(host)
          rule_https = add_rule(rule_https, url, entry_count)
      if scheme == "http":
        http = True
        if redirect:
          cfg['redirect'].append("http://" + host)
        if host not in seen_http:
          seen_http.add(host)
          rule_http = add_rule(rule_http, url, entry_count)

    if http2s and (http or https):
      raise AnsibleFilterError("Mixed http2s and http or https schemes %s (%s) ..." % (urls[0], entry_count))

    create_chain = True
    if 'redirect' in cfg:
      redir = list(set(cfg["redirect"]))
      redirects_list = []
      redirects = []
      if isinstance(redir, string_types):
        redirects_list.append(redir)
      elif is_sequence(redir):
        redirects_list.extend(redir)
      else:
        raise AnsibleFilterError("redirect must be string or list, got %s instead (%s) ..." % (type(redir), entry_count))
      if redirect:
        to = vhost['to']
      else:
        to = urls[0]
      to_host = urlsplit(to).hostname
      to_scheme = urlsplit(to).scheme
      if to_scheme == "http2s":
        to_scheme = "https"
      to = to_scheme + "://" + to_host + "${1}"
      to_file = "move-%s-%s.yaml" % (to_scheme, to_host)
      to_id = hashlib.md5(to_file.encode("utf-8")).hexdigest()[:12]
      for rdir in redirects_list:
        #if isinstance(rdir, string_types):
        #  raise AnsibleFilterError("redirect entry must be string, got %s instead (%s) ..." % (type(rdir), entry_count))
        host = urlsplit(rdir).hostname
        scheme = urlsplit(rdir).scheme
        if not scheme in [ 'http','https','http2s' ]:
          raise AnsibleFilterError("Unsupported url %s for redirect (%s) ..." % (rdir, entry_count))
        if scheme == "http2s":
          url = "http2s://" + host
          if url in seen_redirect:
            raise AnsibleFilterError("redirect url already defined (http2s) %s (%s) ..." % (url, entry_count))
          seen_redirect.add(url)
          redirects.append( { "kind": "http2s", "id": to_id })
          if host not in seen_http:
            seen_http.add(host)
            rule_http = add_rule(rule_http, url, entry_count)
          if host not in seen_https:
            seen_https.add(host)
            rule_https = add_rule(rule_https, url, entry_count)
          if sans_empty:
            sans.append(host)
          create_chain = False
          tls_domains.add(host)
        else:
          url = scheme + "://" + host
          if url in seen_redirect:
            raise AnsibleFilterError("redirect url already defined %s (%s) ..." % (url, entry_count))
          seen_redirect.add(url)
          if scheme == "http":
            http = True
            if host not in seen_http:
              seen_http.add(host)
              rule_http = add_rule(rule_http, url, entry_count)
          if scheme == "https":
            https = True
            tls_domains.add(host)
            if host not in seen_https:
              seen_https.add(host)
              rule_https = add_rule(rule_https, url, entry_count)
            if sans_empty:
              sans.append(host)
          redirects.append( { "kind": "redirect", "id": to_id })
      unique = []
      seen = set()
      for d in redirects:
        t = tuple(sorted(d.items()))
        if t not in seen:
          seen.add(t)
          unique.append(d)
      runtime["redirects"] = unique
      if to not in redirect_target and create_chain:
        chains[to] = { "rule": "(?i)^https?://[^/]+(.+)", "url": to, "host": to_host,  "scheme": to_scheme, "file": to_file, "id": to_id }
        runtime_files.append(to_file)
        redirect_target.add(to)

    runtime["rule"] = { "http": rule_http, "https": rule_https }
    runtime["scheme"] = {}
    runtime["scheme"]["http2s"] = http2s
    runtime["scheme"]["https"] = https
    runtime["scheme"]["http"] = http

    via = cfg.get("entrypoint", cfg.get("via"))
    if via is None:
      http_eps = [ "http" ]
      https_eps = [ "https" ]
    else:
      if isinstance(via, string_types):
        via = [ via ]
      elif not is_sequence(via):
        raise AnsibleFilterError("via must be string or list, got %s instead (%s) ..." % (type(via), entry_count))
      http_eps = []
      https_eps = []
      for ep_name in via:
        if ep_name not in ingress["entrypoint"]:
          raise AnsibleFilterError("vhost entrypoint '%s' is not defined (%s) ..." % (ep_name, entry_count))
        if ingress["entrypoint"][ep_name]["type"] == "http":
          http_eps.append(ep_name)
        else:
          https_eps.append(ep_name)
      if http and not http_eps:
        raise AnsibleFilterError("vhost %s serves http but 'via' lists no http-type entrypoint (%s) ..." % (urls[0], entry_count))
      if https and not https_eps:
        raise AnsibleFilterError("vhost %s serves https but 'via' lists no https-type entrypoint (%s) ..." % (urls[0], entry_count))
    runtime["entrypoints"] = { "http": http_eps, "https": https_eps }

    runtime["san"] = noduplicates(sans)
    runtime["redirect"] = redirect

    seen_san.update(sans)
    wildcards = wildcard_domains(sans)
    wildcard_provider.update({wildcard: tls for wildcard in wildcards})
    config.append(runtime)

  seen_san=list(seen_san)
  ingress["wildcard"] = {}
  ingress["wildcard"]["domain"] = wildcard_domains(seen_san)
  ingress["wildcard"]["provider"] =  wildcard_provider

  # Update vhosts with wildcard domain
  wildcards = ingress["wildcard"]["domain"]
  for entry in config:
    update = False
    for san in entry['san']:
      wildcard = wildcarded(san, wildcards)
      if wildcard != san:
        update = True
      else:
        update = False
        break
    if update:
      tls_domains.discard(san)
      entry['tls'] = wildcard_provider[wildcard]
      entry['san'] = [ wildcard, '*.' + wildcard ]

  ingress["tls_domains"] = list(tls_domains)
  ingress["config"] = config
  ingress["files"] = runtime_files
  ingress.setdefault("acme", {})
  ingress["acme"]["used"] = list(providers)
  ingress["redirect"] = chains
  return ingress

class FilterModule(object):
  def filters(self):
    return {
      'process_ingress_config': process_ingress_config
    }
