from ansible.errors import AnsibleFilterError


def luk_endpoints(endpoint):
    """setup.luk.endpoint as luk reads it: every entry a map with url, and
    pin as a list. An entry may be the URL alone; pins may ride in the
    fragment of the URL (#pin or #pin1,pin2) and in pin (a string or a
    list); both are joined."""
    if endpoint is None:
        return {}
    if not isinstance(endpoint, dict):
        raise AnsibleFilterError("setup.luk.endpoint must be a map of endpoints")
    out = {}
    for name, entry in endpoint.items():
        if isinstance(entry, str):
            entry = {'url': entry}
        elif isinstance(entry, dict):
            entry = dict(entry)
        else:
            raise AnsibleFilterError("setup.luk.endpoint.%s must be a URL or a map" % name)
        url = entry.get('url')
        if not isinstance(url, str) or '://' not in url:
            raise AnsibleFilterError("setup.luk.endpoint.%s: url is required" % name)
        url, _, fragment = url.partition('#')
        pins = [p for p in fragment.split(',') if p]
        listed = entry.get('pin', [])
        if isinstance(listed, str):
            listed = [listed]
        if not isinstance(listed, list):
            raise AnsibleFilterError("setup.luk.endpoint.%s: pin must be a string or a list" % name)
        for p in listed:
            p = str(p)
            if p not in pins:
                pins.append(p)
        entry['url'] = url
        if pins:
            entry['pin'] = pins
        else:
            entry.pop('pin', None)
        out[str(name)] = entry
    return out


class FilterModule(object):
    def filters(self):
        return {'luk_endpoints': luk_endpoints}
