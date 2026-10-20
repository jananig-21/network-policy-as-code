"""Small Jinja filters so the templates need no extra Ansible collections."""
import ipaddress


def to_netmask(cidr):
    return str(ipaddress.ip_network(cidr).netmask)


def to_wildcard(cidr):
    return str(ipaddress.ip_network(cidr).hostmask)


class FilterModule:
    def filters(self):
        return {"to_netmask": to_netmask, "to_wildcard": to_wildcard}
