#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Carlos Rodrigues <cmarodrigues@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = """
---
module: pfsense_dhcp_static
version_added: "0.5.0"
author: Carlos Rodrigues (@cmarodrigues)
short_description: Manage pfSense DHCP static mapping
description:
  - Manage pfSense DHCP static mapping
notes:
options:
  name:
    description: The client name identifier.  At least one of I(name) or I(macaddr) is required.
    type: str
    aliases:
      - cid
  netif:
    description: >
      The network interface.  This defaults to the only enabled DHCP interface if there is only one.
    type: str
  macaddr:
    description:
      - The MAC address. At least one of I(name) or I(macaddr) is required.
      - The module matches MAC addresses case-insensitively and stores them in lowercase.
    type: str
  ipaddr:
    description: The IP address
    type: str
  hostname:
    description: The hostname
    type: str
  descr:
    description: The description
    type: str
  filename:
    description: The filename
    type: str
  rootpath:
    description: The root path
    type: str
  defaultleasetime:
    description: The default lease time
    type: str
  maxleasetime:
    description: The max lease time
    type: str
  gateway:
    description: The gateway
    type: str
  domain:
    description: The domain
    type: str
  winsserver:
    description: The WINS server
    type: list
    elements: str
  dnsserver:
    description: The dns server
    type: list
    elements: str
  ntpserver:
    description: The ntpserver
    type: list
    elements: str
  domainsearchlist:
    description: The domain search list servers
    type: str
  ddnsdomain:
    description: The ddns domain
    type: str
  ddnsdomainprimary:
    description: The ddns primary domain
    type: str
  ddnsdomainsecondary:
    description: The ddns secondary domain
    type: str
  ddnsdomainkeyname:
    description: The ddns domain key name
    type: str
  ddnsdomainkeyalgorithm:
    description: The ddns key algorithm
    type: str
    choices: [ 'hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512' ]
  ddnsdomainkey:
    description: The ddns domain key
    type: str
  tftp:
    description: The TFTP server
    type: str
  ldap:
    description: The ldap server
    type: str
  nextserver:
    description: The next server
    type: str
  filename32:
    description: The filename for 32bits
    type: str
  filename64:
    description: The filename for 64bits
    type: str
  filename32arm:
    description: The filename for 32arm
    type: str
  filename64arm:
    description: The filename for 64arm
    type: str
  uefihttpboot:
    description: UEFI HTTPBoot URL
    type: str
    version_added: "0.5.2"
  numberoptions:
    description: The number options
    type: str
  arp_table_static_entry:
    description: Create an ARP Table Static Entry for this MAC & IP Address pair
    type: bool
    required: false
    default: false
  state:
    description: State in which to leave the configuration
    default: present
    choices: [ "present", "absent" ]
    type: str
"""

EXAMPLES = """
- name: Create DHCP static mapping
  pfsense_dhcp_static:
    name: "test"
    macaddr: "aa:aa:aa:aa:aa:aa"
    ipaddr: "192.168.1.10"
    state: present

- name: Remove DHCP static mapping
  pfsense_dhcp_static:
    name: "test"
    state: absent
"""

RETURN = """
netif:
    description: The selected interface
    returned: success
    type: str
    sample: 'lan'
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.dhcp_static import (
    PFSenseDHCPStaticModule,
    DHCP_STATIC_ARGUMENT_SPEC,
    DHCP_STATIC_REQUIRED_IF,
    DHCP_STATIC_REQUIRED_ONE_OF,
)


def main():
    module = AnsibleModule(
        argument_spec=DHCP_STATIC_ARGUMENT_SPEC, required_if=DHCP_STATIC_REQUIRED_IF, required_one_of=DHCP_STATIC_REQUIRED_ONE_OF, supports_check_mode=True
    )

    pfmodule = PFSenseDHCPStaticModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
