#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, David Rosado <davidrosza0@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '6.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_dhcp_server
version_added: "0.7.0"
author: "David Rosado (@davrosza)"
short_description: Manage pfSense DHCP servers
description:
  - Manage DHCP servers on pfSense
notes:
options:
  state:
    description: State in which to leave the DHCP server
    choices: [ 'present', 'absent' ]
    default: 'present'
    type: str
  interface:
    description: Interface on which to configure the DHCP server
    required: true
    type: str
  enable:
    description: Enable DHCP server on the interface
    type: bool
    default: true
  range_from:
    description: Start of IP address range
    type: str
  range_to:
    description: End of IP address range
    type: str
  failover_peerip:
    description: Failover peer IP address
    type: str
  defaultleasetime:
    description: Default lease time in seconds
    type: int
  maxleasetime:
    description: Maximum lease time in seconds
    type: int
  netmask:
    description: Subnet mask
    type: str
  gateway:
    description: Gateway IP address
    type: str
  domain:
    description: Domain name
    type: str
  domainsearchlist:
    description: Domain search list
    type: str
  ddnsdomain:
    description: DDNS domain
    type: str
  ddnsdomainprimary:
    description: DDNS domain primary server
    type: str
  ddnsdomainkeyname:
    description: DDNS domain key name
    type: str
  ddnsdomainkeyalgorithm:
    description: DDNS domain key algorithm
    type: str
    choices: [ 'hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512' ]
    default: hmac-md5
  ddnsdomainkey:
    description: DDNS domain key
    type: str
  mac_allow:
    description: Allowed MAC addresses
    type: list
    elements: str
  mac_deny:
    description: Denied MAC addresses
    type: list
    elements: str
  ddnsclientupdates:
    description: DDNS client updates
    type: str
    default: 'allow'
    choices: [ 'allow', 'deny', 'ignore' ]
  tftp:
    description: TFTP server
    type: str
  ldap:
    description: LDAP server
    type: str
  nextserver:
    description: Next server
    type: str
  filename:
    description: Filename
    type: str
  filename32:
    description: 32-bit filename
    type: str
  filename64:
    description: 64-bit filename
    type: str
  rootpath:
    description: Root path
    type: str
  numberoptions:
    description: DHCP options currently non applicable
    type: str
  ignorebootp:
    description: Disable BOOTP
    type: bool
  denyunknown:
    description: >
      Enable DHCP to ignore unknown clients. Choices are `disabled` - "Allow all clients", `enabled` - "Allow known clients from any
      interface", and `class` - "Allow known clients from only this interface".  Default is `disabled`.
    type: str
    choices: ['disabled', 'enabled', 'class']
  nonak:
    description: Ignore denied clients
    type: bool
  ignoreclientuids:
    description: Ignore client identifiers
    type: bool
  staticarp:
    description: Enable Static ARP entries
    type: bool
  dhcpinlocaltime:
    description: Change DHCP display lease time from UTC to local time
    type: bool
  statsgraph:
    description: Enable monitoring graphs for lease DHCP statistics
    type: bool
  disablepingcheck:
    description: Enable DHCP ping check
    type: bool
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
"""

EXAMPLES = """
- name: Configure DHCP server on IOT interface
  pfsense_dhcp_server:
    interface: IOT
    enable: true
    range_from: 192.168.1.100
    range_to: 192.168.1.200
    netmask: 255.255.255.0
    gateway: 192.168.1.1
    domain: example.com
    defaultleasetime: 86400
    maxleasetime: 172800

- name: Remove DHCP server from opt1 interface
  pfsense_dhcp_server:
    interface: opt1
    state: absent
"""

RETURN = """
commands:
    description: The set of commands that would be pushed to the remote device.
    returned: always
    type: list
    sample: [
        "create dhcp_server 'IOT', range_from='192.168.1.100', range_to='192.168.1.200', enable='True'",
        "update dhcp_server 'IOT' set domain='example.com'",
        "delete dhcp_server 'opt1'"
    ]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.dhcp_server import PFSenseDHCPServerModule, DHCPSERVER_ARGUMENT_SPEC


def main():
    module = AnsibleModule(
        argument_spec=DHCPSERVER_ARGUMENT_SPEC,
        supports_check_mode=True)
    pfmodule = PFSenseDHCPServerModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
