# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


# These fields follow the pfSense alias deletion checks, with additional
# fields for firewall source ports, outbound NAT, and OpenVPN clients.
OPENVPN_NETWORK_FIELDS = (
    "tunnel_network", "tunnel_networkv6", "local_network", "local_networkv6", "remote_network", "remote_networkv6",
)
ALIAS_REFERENCE_FIELDS = {
    "filter/rule": ("source/address", "source/port", "destination/address", "destination/port"),
    "nat/rule": ("source/address", "source/port", "destination/address", "destination/port", "target", "local-port"),
    "nat/onetoone": ("destination/address",),
    "nat/outbound/rule": (
        "source/network", "source/address", "sourceport", "destination/network", "destination/address", "dstport", "target", "natport",
    ),
    "aliases/alias": ("address",),
    "staticroutes/route": ("network",),
    "openvpn/openvpn-server": OPENVPN_NETWORK_FIELDS,
    "openvpn/openvpn-client": OPENVPN_NETWORK_FIELDS,
    "openvpn/openvpn-csc": OPENVPN_NETWORK_FIELDS,
}
PORT_FIELDS = frozenset(("source/port", "destination/port", "sourceport", "dstport", "natport", "local-port"))


def alias_reference_names(section, field, value):
    """Split a configuration field into possible alias names."""
    if section == "aliases/alias":
        return value.split()
    if section.startswith("openvpn/"):
        return [name.strip() for name in value.split(",")]
    if field in PORT_FIELDS:
        return [name.strip() for name in value.replace(":", "-").split("-")]
    return [value.strip()]
