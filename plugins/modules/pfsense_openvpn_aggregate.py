#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Romain Tiennot (@RomainTie)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {"metadata_version": "1.1",
                    "status": ["preview"],
                    "supported_by": "community"}

DOCUMENTATION = """
---
module: pfsense_openvpn_aggregate
version_added: 0.8.0
author: Romain Tiennot (@RomainTie)
short_description: Manage multiple pfSense OpenVPN servers, clients and client specific overrides
description:
  - Manage multiple pfSense OpenVPN servers, clients and client specific overrides, and delete the ones not listed.
  - config.xml is written once. Then the deleted servers and clients are stopped, and the created or updated ones restarted.
notes:
  - aggregated_* use the same options definitions than pfsense corresponding module
  - With a purge, every entry that no item resolves to is deleted, copies of a listed name included. Servers and clients are
    found by their description, overrides by their common name.
  - A server whose interface (ovpnsN) is assigned cannot be deleted. The module fails, as M(pfsensible.core.pfsense_openvpn_server) does.
  - In check mode, the results list what would be created, updated and deleted, and nothing runs on the firewall.
options:
  aggregated_openvpn_servers:
    description: Dict of OpenVPN servers to apply on the target
    required: False
    type: list
    elements: dict
    suboptions:
      name:
        description: The name of the OpenVPN server.
        required: true
        type: str
      mode:
        description: The server mode.
        choices:
        - p2p_tls
        - p2p_shared_key
        - server_tls
        - server_tls_user
        - server_user
        type: str
      dco:
        description: Enable Data Channel Offload (Supported on Plus versions only)
        default: false
        required: false
        type: bool
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
        choices:
        - present
        - absent
        type: str
      disable:
        description: Is the OpenVPN config disabled?
        default: false
        type: bool
      interface:
        description: The interface for OpenVPN to listen on. Accepts an IP Alias or CARP virtual IP description.
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
        default: UDP4
        choices:
        - UDP4
        - TCP4
        type: str
      dev_mode:
        description: Device mode.
        default: tun
        choices:
        - tun
        - tap
        type: str
      tls:
        description: TLS Key.  If set to 'generate' it will create a key if one does not already exist.  Not valid with p2p_shared_key mode.
        type: str
      tls_type:
        description: Use TLS for authentication ('auth') or encyprtion and authentication ('crypt').  Only used when tls is set.
        default: auth
        required: false
        choices:
        - auth
        - crypt
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
        description: 'Enforce that only hosts with a client certificate can connect (EKU: TLS Web Client Authentication).'
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
        choices:
        - none
        - prime256v1
        - secp384r1
        - secp521r1
        type: str
      data_ciphers_fallback:
        description: Fallback cryptographic algorithm.
        default: AES-256-CBC
        choices:
        - AES-256-CBC
        - AES-256-GCM
        - AES-128-GCM
        - CHACHA20-POLY1305
        type: str
      data_ciphers:
        description: Allowed cryptographic algorithms.
        default:
        - AES-256-GCM
        - AES-128-GCM
        - CHACHA20-POLY1305
        choices:
        - AES-256-CBC
        - AES-256-GCM
        - AES-128-GCM
        - CHACHA20-POLY1305
        type: list
        elements: str
      digest:
        description:
        - 'Auth digest algorithm. The list of valid digest algorithms is determined from the output of C(openvpn --show-digests), but curently includes:'
        - BLAKE2b512, BLAKE2s256, KECCAK-KMAC-128, KECCAK-KMAC-256, MD5, MD5-SHA1, NULL, RIPEMD160, SHA1, SHA224, SHA256,
        - SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHA384, SHA512, SHA512-224, SHA512-256, SHAKE128, SHAKE256
        default: SHA256
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
        default: false
        type: bool
      gwredir6:
        description: Redirect IPv6 gateway.
        default: false
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
        choices:
        - 'no'
        - asym
        - 'yes'
        type: str
      compression:
        description:
        - Allowed compression to be used with this VPN instance.
        - ''''' => Disable Compression [Omit Preference]'
        - '''none'' => Disable Compression, retain compression packet framing [compress]'
        - '''stub'' => Enable Compression (stub) [compress stub]'
        - '''stub-v2'' => Enable Compression (stub v2) [compress stub-v2]'
        - '''lz4'' => LZ4 Compression [compress lz4]'
        - '''lz4-v2'' => LZ4 Compression v2 [compress lz4-v2]'
        - '''lzo'' => LZO Compression [compress lzo, equivalent to comp-lzo yes for compatibility]'
        - '''noadapt'' => Omit Preference, + Disable Adaptive LZO Compression [Legacy style, comp-noadapt]'
        - '''adaptive'' => Adaptive LZO Compression [Legacy style, comp-lzo adaptive]'
        - '''yes'' => LZO Compression [Legacy style, comp-lzo yes]'
        - '''no'' => No LZO Compression [Legacy style, comp-lzo no]'
        default: ''
        choices:
        - ''
        - none
        - stub
        - stub-v2
        - lz4
        - lz4-v2
        - lzo
        - noadapt
        - adaptive
        - 'yes'
        - 'no'
        type: str
      compression_push:
        description: Push the selected Compression setting to connecting clients.
        default: false
        type: bool
      passtos:
        description: Set the TOS IP header value of tunnel packets to match the encapsulated packet value.
        default: false
        type: bool
      client2client:
        description: Allow communication between clients connected to this server.
        default: false
        type: bool
      dynamic_ip:
        description: Allow connected clients to retain their connections if their IP address changes.
        default: false
        type: bool
      topology:
        description: The method used to supply a virtual adapter IP address to clients when using TUN mode on IPv4.
        default: subnet
        choices:
        - net30
        - subnet
        type: str
      inactive_seconds:
        description: Causes OpenVPN to close a client connection after n seconds of inactivity on the TUN/TAP device.
        default: 0
        type: int
      keepalive_interval:
        description:
        - 'keepalive helper uses interval and timeout parameters to define ping and ping-restart values as follows:'
        - ping = interval
        - ping-restart = timeout*2
        - push ping = interval
        - push ping-restart = timeout
        default: 10
        type: int
      keepalive_timeout:
        description:
        - 'keepalive helper uses interval and timeout parameters to define ping and ping-restart values as follows:'
        - ping = interval
        - ping-restart = timeout*2
        - push ping = interval
        - push ping-restart = timeout
        default: 60
        type: int
      exit_notify:
        description:
        - Send an explicit exit notification to connected clients/peers when restarting or shutting down, so they may immediately disconnect rather than waiting
        - for a timeout. In SSL/TLS Server modes, clients may be directed to reconnect or use the next server. This option is ignored in Peer-to-Peer Shared Key
        - mode and in SSL/TLS mode with a blank or /30 tunnel network as it will cause the server to exit and not restart. This feature is not currently
        - compatible with DCO mode.
        - '''none'' => Disabled'
        - '''1'' => Reconnect to this server / Retry once'
        - '''2'' => Reconnect to next server / Retry twice'
        default: none
        choices:
        - none
        - '1'
        - '2'
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
        default: false
      create_gw:
        description: Which gateway types to create.
        default: both
        choices:
        - both
        - v4only
        - v6only
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
  aggregated_openvpn_clients:
    description: Dict of OpenVPN clients to apply on the target
    required: False
    type: list
    elements: dict
    suboptions:
      name:
        description: The name of the OpenVPN configuration.
        required: true
        type: str
      mode:
        description: The client mode.
        required: false
        default: p2p_tls
        choices:
        - p2p_tls
        - p2p_shared_key
        type: str
      authmode:
        description: Authentication clients.  Required if mode == client_tls_user.
        default: []
        type: list
        elements: str
      state:
        description: State in which to leave the OpenVPN config.
        default: present
        choices:
        - present
        - absent
        type: str
      disable:
        description: Is the OpenVPN config disabled.
        default: false
        type: bool
      interface:
        description: The local interface used by the OpenVPN client. Accepts an IP Alias or CARP virtual IP description.
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
        choices:
        - UDP4
        - TCP4
        type: str
      dev_mode:
        description: Device mode.
        default: tun
        choices:
        - tun
        - tap
        type: str
      tls:
        description: TLS Key.  If set to 'generate' it will create a key if one does not already exist.  Not valid with p2p_shared_key mode.
        type: str
      tls_type:
        description: Use TLS for authentication ('auth') or encyprtion and authentication ('crypt').  Only used when tls is set.
        default: auth
        required: false
        choices:
        - auth
        - crypt
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
      strictusercn:
        description: Enforce a match between the common name of the client certificate and the username given at login.
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
        choices:
        - none
        - prime256v1
        - secp384r1
        - secp521r1
        type: str
      data_ciphers_fallback:
        description: Fallback cryptographic algorithm.
        default: AES-256-CBC
        choices:
        - AES-256-CBC
        - AES-256-GCM
        - AES-128-GCM
        - CHACHA20-POLY1305
        type: str
      data_ciphers:
        description: Allowed cryptographic algorithms.
        choices:
        - AES-256-CBC
        - AES-256-GCM
        - AES-128-GCM
        - CHACHA20-POLY1305
        type: list
        elements: str
      ncp_enable:
        description: Enable data encryption negotiation.
        default: false
        type: bool
      digest:
        description:
        - 'Auth digest algorithm. The list of valid digest algorithms is determined from the output of C(openvpn --show-digests), but curently includes:'
        - BLAKE2b512, BLAKE2s256, KECCAK-KMAC-128, KECCAK-KMAC-256, MD5, MD5-SHA1, NULL, RIPEMD160, SHA1, SHA224, SHA256,
        - SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHA384, SHA512, SHA512-224, SHA512-256, SHAKE128, SHAKE256
        default: SHA256
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
        default: false
        type: bool
      gwredir6:
        description: Redirect IPv6 gateway.
        default: false
        type: bool
      maxclients:
        description: The maximum number of clients allowed to concurrently connect to this client.
        default: null
        type: int
      compression:
        description: Allowed compression to be used with this VPN instance.
        default: adaptive
        choices:
        - adaptive
        - ''
        type: str
      compression_push:
        description: Push the selected Compression setting to connecting clients.
        default: false
        type: bool
      passtos:
        description: Set the TOS IP header value of tunnel packets to match the encapsulated packet value.
        default: false
        type: bool
      client2client:
        description: Allow communication between clients connected to this client.
        default: false
        type: bool
      dynamic_ip:
        description: Allow connected clients to retain their connections if their IP address changes.
        default: false
        type: bool
      topology:
        description: The method used to supply a virtual adapter IP address to clients when using TUN mode on IPv4.
        default: subnet
        choices:
        - net30
        - subnet
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
        default: false
        type: bool
      create_gw:
        description: Which gateway types to create.
        default: both
        choices:
        - both
        - v4only
        - v6only
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
  aggregated_openvpn_overrides:
    description: Dict of OpenVPN client specific overrides to apply on the target
    required: False
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the override. The X.509 common name for the client certificate, or the username for VPNs utilizing password authentication.
        - This match is case sensitive.
        required: true
        type: str
      state:
        description: State in which to leave the override
        choices:
        - present
        - absent
        default: present
        type: str
      disable:
        description: Disable this override.
        default: false
        type: bool
      descr:
        description: The description of the override.
        default: null
        type: str
      server_list:
        description: A list of OpenVPN servers this applies to.
        type: list
        elements: str
      block:
        description: Block this client connection based on its common name.
        default: false
        type: bool
      tunnel_network:
        description: IPv4 virtual network used for private communications between this server and client hosts expressed using CIDR notation.
        default: null
        type: str
      tunnel_networkv6:
        description: IPv6 virtual network used for private communications between this server and client hosts expressed using CIDR notation.
        default: null
        type: str
      local_network:
        description: IPv4 networks that will be accessible from the remote endpoint.
        default: null
        type: str
      local_networkv6:
        description: IPv6 networks that will be accessible from the remote endpoint.
        default: null
        type: str
      remote_network:
        description: IPv4 networks that will be routed through the tunnel.
        default: null
        type: str
      remote_networkv6:
        description: IPv6 networks that will be routed through the tunnel.
        default: null
        type: str
      gwredir:
        description: Redirect IPv4 gateway.
        default: false
        type: bool
      push_reset:
        description: Prevent this client from receiving any server-defined client settings.
        default: false
        type: bool
      netbios_enable:
        description: Enable NetBIOS over TCP/IP.
        default: false
        type: bool
      netbios_ntype:
        description:
        - 'NetBIOS Node Type. Possible options: b-node (broadcasts), p-node (point-to-point name queries to a WINS server),'
        - m-node (broadcast then query name server), and h-node (query name server, then broadcast). Default is 'none'.
        type: str
        choices:
        - none
        - b-node
        - p-node
        - m-node
        - h-node
      netbios_scope:
        description:
        - A NetBIOS Scope ID provides an extended naming service for NetBIOS over TCP/IP. The NetBIOS scope ID isolates NetBIOS traffic on a single network to
        - only those nodes with the same NetBIOS scope ID.
        type: str
      wins_server_enable:
        description: Provide a WINS server list to clients,
        type: bool
        default: false
      custom_options:
        description: Additional options to add for this client specific override, separated by a semicolon.
        type: str
  purge_openvpn_servers:
    description: delete all the OpenVPN servers that are not defined into aggregated_openvpn_servers
    required: False
    default: False
    type: bool
  purge_openvpn_clients:
    description: delete all the OpenVPN clients that are not defined into aggregated_openvpn_clients
    required: False
    default: False
    type: bool
  purge_openvpn_overrides:
    description: delete all the OpenVPN overrides that are not defined into aggregated_openvpn_overrides
    required: False
    default: False
    type: bool
"""

EXAMPLES = """
- name: Remote access server and its overrides, the others deleted
  pfsensible.core.pfsense_openvpn_aggregate:
    aggregated_openvpn_servers:
      - { name: Remote access, mode: server_tls_user, authmode: [Local Database], ca: OpenVPN CA, cert: OpenVPN server, tunnel_network: 10.8.0.0/24 }
    aggregated_openvpn_overrides:
      - { name: alice, server_list: [Remote access], custom_options: "ifconfig-push 10.8.0.10 255.255.255.0" }
    purge_openvpn_servers: true
    purge_openvpn_overrides: true

- name: Only show the OpenVPN clients that are not listed
  pfsensible.core.pfsense_openvpn_aggregate:
    aggregated_openvpn_clients:
      - { name: Branch office, server_addr: vpn.example.com, ca: OpenVPN CA, cert: Branch office }
    purge_openvpn_clients: true
  check_mode: true
"""

RETURN = """
result_openvpn_servers:
    description: the set of OpenVPN server commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["create openvpn_server 'Remote access', description='Remote access'", "delete openvpn_server 'old'"]
result_openvpn_clients:
    description: the set of OpenVPN client commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["update openvpn 'Branch office' set ", "delete openvpn 'old'"]
result_openvpn_overrides:
    description: the set of OpenVPN override commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["create openvpn_override 'alice', common_name='alice'", "delete openvpn_override 'bob'"]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.pfsense import PFSenseModule
from ansible_collections.pfsensible.core.plugins.module_utils.openvpn_client import (
    PFSenseOpenVPNClientModule,
    OPENVPN_CLIENT_ARGUMENT_SPEC,
    OPENVPN_CLIENT_REQUIRED_IF
)
from ansible_collections.pfsensible.core.plugins.module_utils.openvpn_override import (
    PFSenseOpenVPNOverrideModule,
    OPENVPN_OVERRIDE_ARGUMENT_SPEC,
    OPENVPN_OVERRIDE_REQUIRED_IF,
    php_string
)
from ansible_collections.pfsensible.core.plugins.module_utils.openvpn_server import (
    PFSenseOpenVPNServerModule,
    OPENVPN_SERVER_ARGUMENT_SPEC,
    OPENVPN_SERVER_REQUIRED_IF
)

RESYNC = ("foreach (config_get_path('openvpn/openvpn-{mode}', []) as $ovpn) {{ "
          "if (in_array($ovpn['vpnid'], array({vpnids}), true)) {{ openvpn_resync('{mode}', $ovpn); }} }}\n")
RESYNC_CSC = ("foreach (config_get_path('openvpn/openvpn-csc', []) as $csc) {{ "
              "if (in_array($csc['common_name'], array({names}), true)) {{ openvpn_resync_csc($csc); }} }}\n")


class PFSenseModuleOpenVPNAggregate(object):
    """ module managing pfsense aggregated OpenVPN servers, clients and overrides """

    def __init__(self, module):
        self.module = module
        self.pfsense = PFSenseModule(module)
        self.pfsense_servers = PFSenseOpenVPNServerModule(module, self.pfsense)
        self.pfsense_clients = PFSenseOpenVPNClientModule(module, self.pfsense)
        self.pfsense_overrides = PFSenseOpenVPNOverrideModule(module, self.pfsense)
        # What to run once config.xml is written: the entries deleted, then the ones to restart
        self.deleted = []
        self.resync = dict(server=[], client=[], csc=[])

    def run(self, pfmodule, mode, want, purge, tag, field, argument_spec):
        """ process input params to add/update/delete entries, then delete the others if required """
        if want is None:
            return

        kept = set()
        for params in want:
            commands = len(pfmodule.result["commands"])
            pfmodule.run(params)
            changed = len(pfmodule.result["commands"]) > commands
            if params["state"] == "present":
                kept.add(id(pfmodule.target_elt))
                if changed:
                    self.resync[mode].append(pfmodule.obj["common_name"] if mode == "csc" else str(pfmodule.result["vpnid"]))
            elif changed:
                self._deleted(pfmodule, mode)

        # delete every other entry by element: copies of a listed name, or entries without a name, included
        if purge:
            defaults = dict((name, option.get("default")) for name, option in argument_spec.items())
            for elt in pfmodule.root_elt.findall(tag):
                if id(elt) in kept:
                    continue
                name = elt.findtext(field) or ""
                pfmodule.params = dict(defaults, name=name, state="absent")
                pfmodule.obj = {field: name}
                pfmodule.target_elt = elt
                pfmodule._remove()
                self._deleted(pfmodule, mode)

    def _deleted(self, pfmodule, mode):
        """ keep the PHP that stops a deleted entry """
        if mode == "csc":
            before = pfmodule.diff["before"]
            self.deleted.append("openvpn_delete_csc(array('common_name' => {0}, 'server_list' => {1}));\n".format(
                php_string(before.get("common_name")), php_string(before.get("server_list"))))
        else:
            self.deleted.append("openvpn_delete('{0}', array('vpnid' => '{1}'));\n".format(mode, pfmodule.result["vpnid"]))

    def _update(self):
        """ stop the deleted entries and restart the changed ones """
        cmd = "require_once('openvpn.inc');\n" + "".join(self.deleted)
        if self.resync["server"] or self.resync["client"]:
            cmd += "alias_make_table();\n"
        for mode in ("server", "client"):
            if self.resync[mode]:
                cmd += RESYNC.format(mode=mode, vpnids=", ".join(php_string(vpnid) for vpnid in self.resync[mode]))
        if self.resync["server"]:
            cmd += "openvpn_resync_csc_all();\n"
        elif self.resync["csc"]:
            cmd += RESYNC_CSC.format(names=", ".join(php_string(name) for name in self.resync["csc"]))
        return self.pfsense.phpshell(cmd)

    def commit_changes(self):
        """ apply changes and exit module """
        stdout = ""
        stderr = ""
        changed = (
            self.pfsense_servers.result["changed"] or self.pfsense_clients.result["changed"] or self.pfsense_overrides.result["changed"]
        )

        if changed and not self.module.check_mode:
            self.pfsense.write_config(descr="aggregated change")
            (dummy, stdout, stderr) = self._update()

        result = {}
        result["result_openvpn_servers"] = self.pfsense_servers.result["commands"]
        result["result_openvpn_clients"] = self.pfsense_clients.result["commands"]
        result["result_openvpn_overrides"] = self.pfsense_overrides.result["commands"]
        result["changed"] = changed
        result["stdout"] = stdout
        result["stderr"] = stderr
        self.module.exit_json(**result)


def main():
    argument_spec = dict(
        aggregated_openvpn_servers=dict(type="list", elements="dict", options=OPENVPN_SERVER_ARGUMENT_SPEC, required_if=OPENVPN_SERVER_REQUIRED_IF),
        aggregated_openvpn_clients=dict(type="list", elements="dict", options=OPENVPN_CLIENT_ARGUMENT_SPEC, required_if=OPENVPN_CLIENT_REQUIRED_IF),
        aggregated_openvpn_overrides=dict(type="list", elements="dict", options=OPENVPN_OVERRIDE_ARGUMENT_SPEC, required_if=OPENVPN_OVERRIDE_REQUIRED_IF),
        purge_openvpn_servers=dict(default=False, type="bool"),
        purge_openvpn_clients=dict(default=False, type="bool"),
        purge_openvpn_overrides=dict(default=False, type="bool"),
    )

    required_one_of = [[
        "aggregated_openvpn_servers",
        "aggregated_openvpn_clients",
        "aggregated_openvpn_overrides",
    ]]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=required_one_of,
        supports_check_mode=True)

    pfmodule = PFSenseModuleOpenVPNAggregate(module)
    params = module.params

    # servers first: overrides find them by name
    pfmodule.run(pfmodule.pfsense_servers, "server", params["aggregated_openvpn_servers"], params["purge_openvpn_servers"],
                 "openvpn-server", "description", OPENVPN_SERVER_ARGUMENT_SPEC)
    pfmodule.run(pfmodule.pfsense_clients, "client", params["aggregated_openvpn_clients"], params["purge_openvpn_clients"],
                 "openvpn-client", "description", OPENVPN_CLIENT_ARGUMENT_SPEC)
    pfmodule.run(pfmodule.pfsense_overrides, "csc", params["aggregated_openvpn_overrides"], params["purge_openvpn_overrides"],
                 "openvpn-csc", "common_name", OPENVPN_OVERRIDE_ARGUMENT_SPEC)

    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
