#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
module: pfsense_virtual_ip_carp
short_description: Manage a CARP virtual IP on pfSense
version_added: 0.8.0
author: pfsensible contributors (@pfsensible)
description:
  - Manage the address and advertisement settings of a CARP virtual IP on one appliance.
options:
  address:
    description:
      - IPv4 or IPv6 address with the interface prefix length, such as C(192.0.2.11/24).
      - The address identifies the VIP. For deletion the prefix is optional.
    type: str
    required: true
  interface:
    description: Assigned pfSense interface name or description. Required when O(state=present).
    type: str
  vhid:
    description: Virtual host ID in the range 1 to 255. Required when O(state=present).
    type: int
  password:
    description: Shared CARP password. Required when O(state=present).
    type: str
  advbase:
    description: Advertisement base interval in seconds, from 1 to 254.
    type: int
    default: 1
  advskew:
    description: Advertisement skew in units of 1/256 second, from 0 to 254.
    type: int
    default: 0
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
- name: Manage a CARP virtual IP on pfSense
  pfsensible.core.pfsense_virtual_ip_carp:
    address: 192.0.2.11/24
    interface: lan
    vhid: 11
    password: "{{ vault_carp_password }}"
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
    run_virtual_ip("carp")


if __name__ == "__main__":
    main()
