#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019-2022, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_openvpn_server
version_added: 0.5.0
author: Orion Poplawski (@opoplawski)
short_description: Manage pfSense OpenVPN server configuration
description:
  - Manage pfSense OpenVPN server configuration
notes:
options:
  name:
    description: The name of the OpenVPN server.
    required: true
    type: str
  mode:
    description: The server mode.
    choices: ["p2p_tls", "p2p_shared_key", "server_tls", "server_tls_user", "server_user"]
    type: str
  authmode:
    description:
      - Authentication servers. Required if mode == server_tls_user.
      - Use 'Local Database' for authentication against the local pfSense user database.
    default: []
    type: list
    elements: str
  state:
    description: State in which to leave the OpenVPN config.
    default: present
    choices: ["present", "absent"]
    type: str
  disable:
    description: Is the OpenVPN config disabled?
    default: false
    type: bool
  interface:
    description: The interface for OpenVPN to listen on.
    required: false
    default: wan
    type: str
  local_port:
    description: The port for OpenVPN to listen on.
    required: false
    default: 1194
    type: int
  protocol:
    description: The protocol used for the connection.
    default: 'UDP4'
    choices: ['UDP4', 'TCP4']
    type: str
  dev_mode:
    description: Device mode.
    default: tun
    choices: ['tun', 'tap']
    type: str
  tls:
    description: TLS Key.  If set to 'generate' it will create a key if one does not already exist.  Not valid with p2p_shared_key mode.
    type: str
  tls_type:
    description: Use TLS for authentication ('auth') or encyprtion and authentication ('crypt').  Only used when tls is set.
    default: 'auth'
    required: false
    choices: ["auth", "crypt"]
    type: str
  ca:
    description: Certificate Authority name.
    type: str
  crl:
    description: Certificate Revocation List name.
    type: str
  cert:
    description: Server certificate name.
    type: str
  cert_depth:
    description: Depth of certificates to check.
    required: false
    default: 1
    type: int
  strictusercn:
    description: Enforce a match between the common name of the client certificate and the username given at login.
    default: false
    type: bool
  remote_cert_tls:
    description: Enforce that only hosts with a client certificate can connect (EKU: "TLS Web Client Authentication").
    default: false
    type: bool
  shared_key:
    description: Pre-shared key for shared key modes.  If set to 'generate' it will create a key if one does not already exist.
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
    choices: ["none", "prime256v1", "secp384r1", "secp521r1"]
    type: str
  data_ciphers_fallback:
    description: Fallback cryptographic algorithm.
    default: AES-256-CBC
    choices: ['AES-256-CBC', 'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305']
    type: str
  data_ciphers:
    description: Allowed cryptographic algorithms.
    default: ['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305']
    choices: ['AES-256-CBC', 'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305']
    type: list
    elements: str
  ncp_enable:
    description: Enable data encryption negotiation.
    default: true
    type: bool
  digest:
    description: Auth digest algorithm.
    default: SHA256
    choices: ['SHA256', 'SHA1']
    type: str
  tunnel_network:
    description: IPv4 virtual network used for private communications between this server and client hosts expressed using CIDR notation.
    default: ''
    type: str
  tunnel_networkv6:
    description: IPv6 virtual network used for private communications between this server and client hosts expressed using CIDR notation.
    default: ''
    type: str
  local_network:
    description: IPv4 networks that will be accessible from the remote endpoint.
    default: ''
    type: str
  local_networkv6:
    description: IPv6 networks that will be accessible from the remote endpoint.
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
    description: The maximum number of clients allowed to concurrently connect to this server.
    default: null
    type: int
  allow_compression:
    description:
      - Allow compression to be used with this VPN instance.
      - Compression can potentially increase throughput but may allow an attacker to extract secrets if they can control compressed plaintext traversing the
      - VPN (e.g. HTTP). Before enabling compression, consult information about the VORACLE, CRIME, TIME, and BREACH attacks against TLS to decide if the use
      - case for this specific VPN is vulnerable to attack.
      - Asymmetric compression allows an easier transition when connecting with older peers.
    default: 'no'
    choices: ['no', 'asym', 'yes']
    type: str
  compression:
    description:
      - Allowed compression to be used with this VPN instance.
      - "'' => Disable Compression [Omit Preference]"
      - "'none' => Disable Compression, retain compression packet framing [compress]"
      - "'stub' => Enable Compression (stub) [compress stub]"
      - "'stub-v2' => Enable Compression (stub v2) [compress stub-v2]"
      - "'lz4' => LZ4 Compression [compress lz4]"
      - "'lz4-v2' => LZ4 Compression v2 [compress lz4-v2]"
      - "'lzo' => LZO Compression [compress lzo, equivalent to comp-lzo yes for compatibility]"
      - "'noadapt' => Omit Preference, + Disable Adaptive LZO Compression [Legacy style, comp-noadapt]"
      - "'adaptive' => Adaptive LZO Compression [Legacy style, comp-lzo adaptive]"
      - "'yes' => LZO Compression [Legacy style, comp-lzo yes]"
      - "'no' => No LZO Compression [Legacy style, comp-lzo no]"
    default: ''
    choices: ['', 'none', 'stub', 'stub-v2', 'lz4', 'lz4-v2', 'lzo', 'noadapt', 'adaptive', 'yes', 'no']
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
    description: Allow communication between clients connected to this server.
    default: no
    type: bool
  dynamic_ip:
    description: Allow connected clients to retain their connections if their IP address changes.
    default: no
    type: bool
  topology:
    description: The method used to supply a virtual adapter IP address to clients when using TUN mode on IPv4.
    default: subnet
    choices: ['net30', 'subnet']
    type: str
  inactive_seconds:
    description: Causes OpenVPN to close a client connection after n seconds of inactivity on the TUN/TAP device.
    default: 0
    type: int
  keepalive_interval:
    description:
      - keepalive helper uses interval and timeout parameters to define ping and ping-restart values as follows:
      - ping = interval
      - ping-restart = timeout*2
      - push ping = interval
      - push ping-restart = timeout
    default: 10
    type: int
  keepalive_timeout:
    description:
      - keepalive helper uses interval and timeout parameters to define ping and ping-restart values as follows:
      - ping = interval
      - ping-restart = timeout*2
      - push ping = interval
      - push ping-restart = timeout
    default: 60
    type: int
  exit_notify:
    description: 
      - Send an explicit exit notification to connected clients/peers when restarting or shutting down.
      - So they may immediately disconnect rather than waiting for a timeout.
    default: ''
    choices: ['', '1', '2']
    type: str
  dns_domain:
    description: DNS default domain.
    default: ''
    type: str
  dns_server1:
    description: DNS server 1.
    default: ''
    type: str
  dns_server2:
    description: DNS server 2.
    default: ''
    type: str
  dns_server3:
    description: DNS server 3.
    default: ''
    type: str
  dns_server4:
    description: DNS server 4.
    default: ''
    type: str
  push_register_dns:
    description: Push DNS.
    type: bool
    default: no
  create_gw:
    description: Which gateway types to create.
    default: both
    choices: ['both', 'v4only', 'v6only']
    type: str
  verbosity_level:
    description: Verbosity level.
    default: 1
    type: int
  custom_options:
    description: Custom openvpn options.
    required: false
    default: null
    type: str
  username_as_common_name:
    description: Use the authenticated client username instead of the certificate common name (CN).
    default: false
    type: bool
"""

EXAMPLES = """
- name: "Add OpenVPN server"
  pfsense_openvpn_server:
    name: 'OpenVPN Server'
    mode: server_user

- name: "Add OpenVPN server with basic configuration"
  pfsense_openvpn_server:
    name: 'OpenVPN Server Ansible'
    ca: name-your-ca-authority
    cert: name-your-server-certificate
    tunnel_network: 10.21.40.0/24
    local_network: 172.16.3.0/24
    mode: server_tls_user

- name: "Add OpenVPN server with verbose mode and Cloudflare DNS"
  pfsense_openvpn_server:
    name: 'OpenVPN Server Ansible Cloudflare'
    ca: name-your-ca-authority
    cert: name-your-server-certificate
    tunnel_network: 10.10.10.0/24
    local_network: 10.72.40.0/24
    dns_server1: 1.1.1.1
    verbosity_level: 4
    mode: server_user
"""

RETURN = r'''
shared_key:
    description: The generated shared key, base64 encoded
    returned: when `generate` is passed as the shared_key argument and a key is generated.
    type: str
    sample: |-
        IwojIDIwNDggYml0IE9wZW5WUE4gc3RhdGljIGtleQojCi0tLS0tQkVHSU4gT3BlblZQTiBTdGF0aWMga2V5IFYxLS0tLS0KNjFiY2E4MDk0ZmM4YjA3ZTZlMjE3NzRmNTI0YTIyOWYKNGMzZGZhMDVjZ
        Tc2ODVlN2NkNDc1N2I0OGM3ZmMzZDcKYzQzMjhjYzBmMWQ4Yjc2OTk2MjVjNzAwYmVkNzNhNWYKY2RjMjYzMTY2YThlMzVmYTk4NGU0OWVkZDg5MDNkZmMKMDc1ZTQyY2ZlOTM5NzUwYzhmMjc1YTY3MT
        kzMGRmMzEKMDY2Mzk1MjM2ZWRkYWQ3NDc3YmVjZjJmNDgyNzBlMjUKODM1N2JlMGE1MGUzY2Y0ZjllZTEyZTdkMmM4YTY2YzEKODUwNjBlODM5ZWUyMzdjNTZkZmUzNjA4NjU0NDhhYzgKNjhmM2JhYWQ
        4ODNjNDU3NTdlZTVjMWQ4ZDk5ZjM4ZjcKZGNiZDAwZmI3Nzc2ZWFlYjQ1ZmQwOTBjNGNlYTNmMGMKMzgzNDE0ZTJlYmU4MWNiZGIxZmNlN2M2YmFhMDlkMWYKMTU4OGUzNGRkYzUxY2NjOTE5NDNjNTFh
        OTI2OTE3NWQKNzZiZjdhOWI1ZmM3NDAyNmE3MTVkNGVmODVkYzY2Y2UKMWE5MWQwNjNhODIwZDY4MTc0ODlmYjJkZjNmYzY2MmMKMmU2OWZiMzNiMzM5MjdjYjUyNThkZDQ4M2NkNDE0Y2QKMDJhZWE3Z
        jA3MmNhZmEwOTY5Yjg5NWVjYzNiYmExNGQKLS0tLS1FTkQgT3BlblZQTiBTdGF0aWMga2V5IFYxLS0tLS0K
tls:
    description: The generated tls key, base64 encoded
    returned: when `generate` is passed as the tls argument and a key is generated.
    type: str
    sample: |-
        IwojIDIwNDggYml0IE9wZW5WUE4gc3RhdGljIGtleQojCi0tLS0tQkVHSU4gT3BlblZQTiBTdGF0aWMga2V5IFYxLS0tLS0KNjFiY2E4MDk0ZmM4YjA3ZTZlMjE3NzRmNTI0YTIyOWYKNGMzZGZhMDVjZ
        Tc2ODVlN2NkNDc1N2I0OGM3ZmMzZDcKYzQzMjhjYzBmMWQ4Yjc2OTk2MjVjNzAwYmVkNzNhNWYKY2RjMjYzMTY2YThlMzVmYTk4NGU0OWVkZDg5MDNkZmMKMDc1ZTQyY2ZlOTM5NzUwYzhmMjc1YTY3MT
        kzMGRmMzEKMDY2Mzk1MjM2ZWRkYWQ3NDc3YmVjZjJmNDgyNzBlMjUKODM1N2JlMGE1MGUzY2Y0ZjllZTEyZTdkMmM4YTY2YzEKODUwNjBlODM5ZWUyMzdjNTZkZmUzNjA4NjU0NDhhYzgKNjhmM2JhYWQ
        4ODNjNDU3NTdlZTVjMWQ4ZDk5ZjM4ZjcKZGNiZDAwZmI3Nzc2ZWFlYjQ1ZmQwOTBjNGNlYTNmMGMKMzgzNDE0ZTJlYmU4MWNiZGIxZmNlN2M2YmFhMDlkMWYKMTU4OGUzNGRkYzUxY2NjOTE5NDNjNTFh
        OTI2OTE3NWQKNzZiZjdhOWI1ZmM3NDAyNmE3MTVkNGVmODVkYzY2Y2UKMWE5MWQwNjNhODIwZDY4MTc0ODlmYjJkZjNmYzY2MmMKMmU2OWZiMzNiMzM5MjdjYjUyNThkZDQ4M2NkNDE0Y2QKMDJhZWE3Z
        jA3MmNhZmEwOTY5Yjg5NWVjYzNiYmExNGQKLS0tLS1FTkQgT3BlblZQTiBTdGF0aWMga2V5IFYxLS0tLS0K
vpnid:
    description: The vpnid number of the OpenVPN server instance.
    returned: always
    type: int
    sample: 1
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.openvpn_server import (
    PFSenseOpenVPNServerModule,
    OPENVPN_SERVER_ARGUMENT_SPEC,
    OPENVPN_SERVER_REQUIRED_IF
)


def main():
    module = AnsibleModule(
        argument_spec=OPENVPN_SERVER_ARGUMENT_SPEC,
        required_if=OPENVPN_SERVER_REQUIRED_IF,
        supports_check_mode=True)

    pfopenvpn = PFSenseOpenVPNServerModule(module)
    pfopenvpn.run(module.params)
    pfopenvpn.commit_changes()


if __name__ == '__main__':
    main()
