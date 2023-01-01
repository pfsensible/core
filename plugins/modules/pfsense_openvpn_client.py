#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019-2021, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_openvpn_client
short_description: Manage pfSense OpenVPN configuration
description:
  - Manage pfSense OpenVPN configuration
version_added: 0.5.0
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name of the OpenVPN configuration.
    required: true
    type: str
  mode:
    description: The client mode.
    required: false
    default: p2p_tls
    choices: [ "p2p_tls", "p2p_shared_key" ]
    type: str
  authmode:
    description: Authentication clients.  Required if mode == client_tls_user.
    default: []
    type: list
    elements: str
  state:
    description: State in which to leave the OpenVPN config.
    default: present
    choices: [ "present", "absent" ]
    type: str
  disable:
    description: Is the OpenVPN config disabled.
    default: false
    type: bool
  interface:
    description: The interface for OpenVPN to listen on.
    required: false
    default: wan
    type: str
  server_addr:
    description: The address for OpenVPN to connect to.
    required: true
    type: str
  server_port:
    description: The port for OpenVPN to connect to.
    required: false
    default: 1194
    type: int
  protocol:
    description: The protocol.
    default: UDP4
    choices: [ 'UDP4', 'TCP4' ]
    type: str
  dev_mode:
    description: Device mode.
    default: tun
    choices: [ 'tun', 'tap' ]
    type: str
  tls:
    description: TLS Key.  If set to 'generate' it will create a key if one does not already exist.
    type: str
  ca:
    description: Certificate Authority name.
    type: str
  crl:
    description: Certificate Revocation List name.
    type: str
  cert:
    description: Client certificate name.
    type: str
  cert_depth:
    description: Depth of certificates to check.
    required: false
    default: 1
    type: int
  strictuserdn:
    description: Enforce a match between the common name of the client certificate and the username given at login.
    default: false
    type: bool
  shared_key:
    description: Pre-shared key for shared key modes.
    type: str
  dh_length:
    description: DH parameter length.
    required: false
    default: 2048
    type: int
  ecdh_curve:
    description: Elliptic Curve to use for key exchange.
    required: false
    default: none
    choices: [ "none", "prime256v1", "secp384r1", "secp521r1" ]
    type: str
  data_ciphers_fallback:
    description: Fallback cryptographic algorithm.
    default: AES-256-CBC
    choices: [ 'AES-256-CBC', 'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305' ]
    type: str
  data_ciphers:
    description: Allowed cryptographic algorithms.
    choices: [ 'AES-256-CBC', 'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305' ]
    type: list
    elements: str
  ncp_enable:
    description: Enable data encryption negotiation.
    default: no
    type: bool
  digest:
    description: Auth digest algorithm.
    default: SHA256
    choices: [ 'SHA256', 'SHA1' ]
    type: str
  tunnel_network:
    description: IPv4 virtual network used for private communications between this client and client hosts expressed using CIDR notation.
    default: ''
    type: str
  tunnel_networkv6:
    description: IPv6 virtual network used for private communications between this client and client hosts expressed using CIDR notation.
    default: ''
    type: str
  remote_network:
    description: IPv4 networks that will be routed through the tunnel.
    default: ''
    type: str
  remote_networkv6:
    description: IPv6 networks that will be routed through the tunnel.
    default: ''
    type: str
  gwredir:
    description: Redirect IPv4 gateway.
    default: no
    type: bool
  gwredir6:
    description: Redirect IPv6 gateway.
    default: no
    type: bool
  maxclients:
    description: The maximum number of clients allowed to concurrently connect to this client.
    default: null
    type: int
  compression:
    description: Allowed compression to be used with this VPN instance.
    default: adaptive
    choices: ['adaptive', '']
    type: str
  compression_push:
    description: Push the selected Compression setting to connecting clients.
    default: no
    type: bool
  passtos:
    description: Set the TOS IP header value of tunnel packets to match the encapsulated packet value.
    default: no
    type: bool
  client2client:
    description: Allow communication between clients connected to this client.
    default: no
    type: bool
  dynamic_ip:
    description: Allow connected clients to retain their connections if their IP address changes.
    default: no
    type: bool
  topology:
    description: The method used to supply a virtual adapter IP address to clients when using TUN mode on IPv4.
    default: subnet
    choices: ['net30','subnet']
    type: str
  dns_domain:
    description: DNS default domain.
    default: ''
    type: str
  dns_client1:
    description: DNS client 1.
    default: ''
    type: str
  dns_client2:
    description: DNS client 2.
    default: ''
    type: str
  dns_client3:
    description: DNS client 3.
    default: ''
    type: str
  dns_client4:
    description: DNS client 4.
    default: ''
    type: str
  push_register_dns:
    description: Push DNS to client.
    default: no
    type: bool
  create_gw:
    description: Which gateway types to create.
    default: both
    choices: ['both']
    type: str
  verbosity_level:
    description: Verbosity level.
    default: 3
    type: int
  custom_options:
    description: Custom openvpn options.
    required: false
    default: null
    type: str
'''

EXAMPLES = r'''
- name: "Add OpenVPN client"
  pfsense_openvpn_client:
    name: 'OpenVPN Client'
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.openvpn_client import (
    PFSenseOpenVPNClientModule,
    OPENVPN_CLIENT_ARGUMENT_SPEC,
    OPENVPN_CLIENT_REQUIRED_IF
)


def main():
    module = AnsibleModule(
        argument_spec=OPENVPN_CLIENT_ARGUMENT_SPEC,
        required_if=OPENVPN_CLIENT_REQUIRED_IF,
        supports_check_mode=True)

    pfopenvpn = PFSenseOpenVPNClientModule(module)
    pfopenvpn.run(module.params)
    pfopenvpn.commit_changes()


if __name__ == '__main__':
    main()
