#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2021-2022, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_interface
version_added: 0.1.0
author: Frederic Bor (@f-bor)
short_description: Manage pfSense interfaces
description:
  - Manage pfSense interfaces.
notes:
options:
  state:
    description: State in which to leave the interface.
    choices: [ "present", "absent" ]
    default: present
    type: str
  descr:
    description: Description (name) for the interface.
    required: true
    type: str
  interface:
    description: Network port to which assign the interface.
    type: str
  interface_descr:
    description: Network port descr to which assign the interface.
    type: str
  enable:
    description: Enable interface.
    default: no
    type: bool
  ipv4_type:
    description: IPv4 Configuration Type.
    choices: [ "none", "static", "dhcp" ]
    default: 'none'
    type: str
  ipv6_type:
    description: IPv4 Configuration Type.
    choices: [ "none", "static", "slaac" ]
    default: 'none'
    type: str
  mac:
    description: Used to modify ("spoof") the MAC address of this interface.
    required: false
    type: str
  mtu:
    description: Maximum transmission unit
    required: false
    type: int
  mss:
    description: MSS clamping for TCP connections.
    required: false
    type: int
  speed_duplex:
    description: Set speed and duplex mode for this interface.
    required: false
    default: autoselect
    type: str
  ipv4_address:
    description: IPv4 Address.
    required: false
    type: str
  ipv4_prefixlen:
    description: IPv4 subnet prefix length.
    required: false
    default: 24
    type: int
  ipv4_gateway:
    description: IPv4 gateway for this interface.
    required: false
    type: str
  ipv6_address:
    description: IPv6 Address.
    required: false
    type: str
  ipv6_prefixlen:
    description: IPv6 subnet prefix length.
    required: false
    default: 128
    type: int
  ipv6_gateway:
    description: IPv6 gateway for this interface.
    required: false
    type: str
  blockpriv:
    description: Blocks traffic from IP addresses that are reserved for private networks.
    required: false
    type: bool
  blockbogons:
    description: Blocks traffic from reserved IP addresses (but not RFC 1918) or not yet assigned by IANA.
    required: false
    type: bool
  slaacusev4iface:
    description: IPv6 will use the IPv4 connectivity link (PPPoE). Only used when ipv6_type is slaac.
    required: false
    type: bool
    version_added: 0.6.2
"""

EXAMPLES = """
- name: Add interface
  pfsense_interface:
    descr: voice
    interface: mvneta0.100
    enable: True

- name: Remove interface
  pfsense_interface:
    state: absent
    descr: voice
    interface: mvneta0.100
"""

RETURN = """
commands:
    description: The set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: [
        "create interface 'voice', port='mvneta0.100', speed_duplex='autoselect', enable='True'",
        "delete interface 'voice'"
    ]
ifname:
    description: The pseudo-device name of the interface.
    returned: always
    type: str
    sample: opt1
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.interface import (
    PFSenseInterfaceModule,
    INTERFACE_ARGUMENT_SPEC,
    INTERFACE_REQUIRED_IF,
    INTERFACE_MUTUALLY_EXCLUSIVE
)


def main():
    module = AnsibleModule(
        argument_spec=INTERFACE_ARGUMENT_SPEC,
        required_if=INTERFACE_REQUIRED_IF,
        mutually_exclusive=INTERFACE_MUTUALLY_EXCLUSIVE,
        supports_check_mode=True)

    pfmodule = PFSenseInterfaceModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
