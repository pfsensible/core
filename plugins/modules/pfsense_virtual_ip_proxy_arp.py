#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: pfsense_virtual_ip_proxy_arp
short_description: Manage a Proxy ARP virtual IP on pfSense
version_added: 0.8.0
author: pfsensible contributors (@pfsensible)
description:
  - Configure pfSense to answer ARP for an IPv4 address or subnet on an interface.
options:
  address:
    description:
      - IPv4 address or CIDR network. A bare address is treated as a single C(/32) VIP.
      - The address identifies the VIP. For deletion the prefix is optional.
    type: str
    required: true
  interface:
    description: Assigned pfSense interface name or description. Required when O(state=present).
    type: str
  noexpand:
    description: Disable per-address expansion of an IPv4 network VIP in NAT selectors.
    type: bool
  descr:
    description: Description of the VIP.
    type: str
  state:
    description: Whether the VIP should exist.
    type: str
    choices: [present, absent]
    default: present
"""

EXAMPLES = """
- name: Manage a Proxy ARP virtual IP on pfSense
  pfsensible.core.pfsense_virtual_ip_proxy_arp:
    address: 192.0.2.12
    interface: lan
"""

RETURN = """
commands:
  description: Summary of the changes made to the VIP.
  returned: always
  type: list
  elements: str
"""

from ansible_collections.pfsensible.core.plugins.module_utils.virtual_ip import run_virtual_ip


def main():
    run_virtual_ip("proxyarp")


if __name__ == "__main__":
    main()
