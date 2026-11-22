#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
module: pfsense_virtual_ip_alias
short_description: Manage an IP Alias virtual IP on pfSense
version_added: 0.8.0
author: pfsensible contributors (@pfsensible)
description:
  - Manage an address bound to an interface, localhost, or a CARP VIP.
options:
  address:
    description:
      - IPv4 or IPv6 address with the interface prefix length, such as C(192.0.2.10/24).
      - The address identifies the VIP. For deletion the prefix is optional.
    type: str
    required: true
  interface:
    description:
      - Assigned pfSense interface name or description, C(lo0) for localhost, or the address of a CARP VIP.
      - Required when O(state=present).
    type: str
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
- name: Manage an IP Alias virtual IP on pfSense
  pfsensible.core.pfsense_virtual_ip_alias:
    address: 192.0.2.10/24
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
    run_virtual_ip("ipalias")


if __name__ == "__main__":
    main()
