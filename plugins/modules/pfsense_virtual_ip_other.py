#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: pfsense_virtual_ip_other
short_description: Manage an Other virtual IP on pfSense
version_added: 0.8.0
author: pfsensible contributors (@pfsensible)
description:
  - Make a routed address or network available in pfSense NAT selectors.
options:
  address:
    description:
      - IPv4 or IPv6 address or CIDR network. A bare address is treated as a single host VIP.
      - The address identifies the VIP. For deletion the prefix is optional.
    type: str
    required: true
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
- name: Manage an Other virtual IP on pfSense
  pfsensible.core.pfsense_virtual_ip_other:
    address: 198.51.100.0/28
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
    run_virtual_ip("other")


if __name__ == "__main__":
    main()
