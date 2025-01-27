#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Chris Liu <chris.liu.hk@icloud.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_dns_resolver
version_added: 0.6.0
author: Chris liu (@chris-cyliu), Daniel Huss (@danhuss)
short_description: Manage pfSense DNS resolver (unbound) settings
description:
  - Manage pfSense DNS resolver (unbound) settings
notes:
options:
  state:
    description: Enable/Disable DNS Resolver
    default: present
    choices: [ "present", "absent" ]
    type: str
  port:
    description: Listen Port
    required: false
    default: null
    type: int
  enablessl:
    description: Enable SSL/TLS Service
    required: false
    default: false
    type: bool
  sslcert:
    description: Description of the server certificate to use for SSL/TLS service.
    required: false
    default: ""
    type: str
  tlsport:
    description: SSL/TLS Listen Port
    required: false
    default: null
    type: int
  active_interface:
    description: Interface IPs used by the DNS Resolver for responding to queries from clients.
    required: false
    default: [ "all" ]
    type: list
    elements: str
  outgoing_interface:
    description: Utilize different network interface(s) that the DNS Resolver will use to send queries to authoritative servers and receive their replies.
    required: false
    default: [ "all" ]
    type: list
    elements: str
  system_domain_local_zone_type:
    description: The local-zone type used for the pfSense system domain.
    required: false
    default: "transparent"
    type: str
    choices: [ "deny", "refuse", "static", "transparent", "typetransparent", "redirect", "inform", "inform_deny", "nodefault" ]
  dnssec:
    description: Enable DNSSEC Support
    required: false
    default: false
    type: bool
  forwarding:
    description: DNS Query Forwarding.
    required: false
    default: false
    type: bool
  forward_tls_upstream:
    description: Use SSL/TLS for DNS Query Forwarding.
    required: false
    default: false
    type: bool
  regdhcp:
    description: Register DHCP leases in the DNS Resolver
    required: false
    default: false
    type: bool
  regdhcpstatic:
    description: Register DHCP static mappings in the DNS Resolver
    required: false
    default: false
    type: bool
  regovpnclients:
    description: Register OpenVPN clients in the DNS Resolver
    required: false
    default: false
    type: bool
  custom_options:
    description: additional configuration parameters
    required: false
    default: ""
    type: str
  hosts:
    description: Individual hosts for which the resolver's standard DNS lookup should be overridden.
    required: false
    default: []
    type: list
    elements: dict
    suboptions:
      host:
        description: Name of the host, without the domain part.
        required: true
        type: str
      domain:
        description: Parent domain of the host.
        required: true
        type: str
      ip:
        description: IPv4 or IPv6 comma-separated addresses to be returned for the host
        required: true
        type: str
      descr:
        description: A description may be entered here for administrative reference.
        required: false
        default: ""
        type: str
      aliases:
        description: Additional names for this host.
        required: false
        default: []
        type: list
        elements: dict
        suboptions:
          host:
            description: Name of the host, without the domain part.
            required: true
            type: str
          domain:
            description: Parent domain of the host.
            required: true
            type: str
          description:
            description: A description may be entered here for administrative reference.
            required: true
            type: str
  domainoverrides:
    description: Domains for which the resolver's standard DNS lookup should be overridden.
    required: false
    default: []
    type: list
    elements: dict
    suboptions:
      domain:
        description: Domain whose lookups will be directed to a user-specified DNS lookup server.
        required: true
        type: str
      ip:
        description: IPv4 or IPv6 address of the authoritative DNS server for this domain.
        required: true
        type: str
      forward_tls_upstream:
        description: Use SSL/TLS for DNS Queries forwarded to this server
        required: false
        default: ''
        type: str
      tls_hostname:
        description: An optional TLS hostname used to verify the server certificate when performing TLS Queries.
        required: false
        default: ''
        type: str
      descr:
        description: A description may be entered here for administrative reference.
        required: false
        type: str
  hideidentity:
    description: id.server and hostname.bind queries are refused.
    required: false
    default: true
    type: bool
  hideversion:
    description: version.server and version.bind queries are refused.
    required: false
    default: true
    type: bool
  prefetch:
    description: Message cache elements are prefetched before they expire to help keep the cache up to date.
    required: false
    default: false
    type: bool
  prefetchkey:
    description: DNSKEYs are fetched earlier in the validation process when a Delegation signer is encountered.
    required: false
    default: false
    type: bool
  dnssecstripped:
    description: If enabled, DNSSEC data is required for trust-anchored zones.
    required: false
    default: true
    type: bool
  msgcachesize:
    description: Message cache size in MB
    required: false
    default: 4
    choices: [ 4, 10, 20, 50, 100, 250, 512 ]
    type: int
  outgoing_num_tcp:
    description: Number of outgoing TCP buffers to allocate per thread.
    required: false
    default: 10
    choices: [ 0, 10, 20, 30, 50 ]
    type: int
  incoming_num_tcp:
    description: Number of incoming TCP buffers to allocate per thread.
    required: false
    default: 10
    choices: [ 0, 10, 20, 30, 50 ]
    type: int
  edns_buffer_size:
    description: Number of bytes to advertise as the EDNS reassembly buffer size.
    required: false
    default: "auto"
    choices: [ "auto", "512", "1220", "1232", "1432", "1480", "4096" ]
    type: str
  num_queries_per_thread:
    description: Number of queries that every thread will service simultaneously.
    required: false
    default: 512
    choices: [ 512, 1024, 2048 ]
    type: int
  jostle_timeout:
    description: This timeout (in milliseconds) is used for when the server is very busy.
    required: false
    default: 200
    choices: [ 100, 200, 500, 1000 ]
    type: int
  cache_max_ttl:
    description: The Maximum Time to Live (in seconds) for RRsets and messages in the cache.
    required: false
    default: 86400
    type: int
  cache_min_ttl:
    description: The Minimum Time to Live (in seconds) for RRsets and messages in the cache.
    required: false
    default: 0
    type: int
  infra_host_ttl:
    description: Time to Live, in seconds, for entries in the infrastructure host cache.
    required: false
    default: 900
    choices: [ 60, 120, 300, 600, 900 ]
    type: int
  infra_cache_numhosts:
    description: Number of infrastructure hosts for which information is cached.
    required: false
    default: 10000
    choices: [ 1000, 5000, 10000, 20000, 50000, 100000, 200000 ]
    type: int
  unwanted_reply_threshold:
    description: If enabled, a total number of unwanted replies is kept track of in every thread.
    required: false
    default: "disabled"
    choices: [ "disabled", "5000000", "10000000", "20000000", "40000000", "50000000" ]
    type: str
  log_verbosity:
    description: The level of detail to be logged.
    required: false
    default: 1
    choices: [ 0, 1, 2, 3, 4, 5 ]
    type: int
"""

EXAMPLES = """
- name: Enable DNS Resolver
  pfsense_dns_resolver:
    state: present

- name: Enable DNS Resolver with some options
  pfsense_dns_resolver:
    state: present
    enablessl: true
    sslcert: "webConfigurator default"
    dnssec: true
    regdhcp: true
    regdhcpstatic: true
    hosts:
      - { host: test, domain: home.local, ip: 192.168.1.100, descr: "Example host override",
          aliases: [{ host: test-admin, domain: home.local, description: "Example aliases" }] }

- name: Disable DNS Resolver
  pfsense_dns_resolver:
    state: absent
"""

RETURN = """

"""

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase
from ansible.module_utils.basic import AnsibleModule
import base64

# TODO: access control is not done here
# TODO: alias for DNS record

DNS_RESOLVER_DOMAIN_OVERRIDE_SPEC = dict(
    domain=dict(required=True, type='str'),
    ip=dict(required=True, type='str'),
    descr=dict(type='str'),
    tls_hostname=dict(default='', type='str'),
    forward_tls_upstream=dict(default='', type='str'),
)

DNS_RESOLVER_HOST_ALIAS_SPEC = dict(
    host=dict(required=True, type='str'),
    domain=dict(required=True, type='str'),
    description=dict(required=True, type='str'),
)

DNS_RESOLVER_HOST_SPEC = dict(
    host=dict(required=True, type='str'),
    domain=dict(required=True, type='str'),
    ip=dict(required=True, type='str'),
    descr=dict(default="", type='str'),
    aliases=dict(default=[], type='list', elements='dict', options=DNS_RESOLVER_HOST_ALIAS_SPEC),
)

DNS_RESOLVER_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),

    # General Settings
    port=dict(default=None, type='int'),
    enablessl=dict(default=False, type='bool'),
    sslcert=dict(default="", type='str'),  # need transform
    tlsport=dict(default=None, type='int'),
    active_interface=dict(default=["all"], type='list', elements='str'),
    outgoing_interface=dict(default=["all"], type='list', elements='str'),
    # TODO: Strict Outgoing Network interface Binding: check box option
    system_domain_local_zone_type=dict(default='transparent', choices=['deny', 'refuse', 'static', 'transparent', 'typetransparent', 'redirect', 'inform',
                                                                       'inform_deny', 'nodefault']),
    dnssec=dict(default=False, type='bool'),
    # TODO: Python Module: Enable the Python Module. These 3 options omited when disabled
    # python=dict(default=False, type='bool'),
    # python_order=dict(default="pre_validator", type='str', choices=["pre_validator", "post_validator"]),
    # python_script=dict(default="", type='str'), #Not sure what this is or how to handle it.
    forwarding=dict(default=False, type='bool'),
    forward_tls_upstream=dict(default=False, type='bool'),
    regdhcp=dict(default=False, type='bool'),
    regdhcpstatic=dict(default=False, type='bool'),
    regovpnclients=dict(default=False, type='bool'),
    custom_options=dict(default="", type='str'),
    hosts=dict(default=[], type='list', elements='dict', options=DNS_RESOLVER_HOST_SPEC),
    domainoverrides=dict(default=[], type='list', elements='dict', options=DNS_RESOLVER_DOMAIN_OVERRIDE_SPEC),
    # Advanced Settings
    hideidentity=dict(default=True, type='bool'),
    hideversion=dict(default=True, type='bool'),
    # TODO: Query Name Minimization
    # TODO: Strict Query Name Minimization
    prefetch=dict(default=False, type='bool'),
    prefetchkey=dict(default=False, type='bool'),
    dnssecstripped=dict(default=True, type='bool'),
    # TODO: Serve Expired
    # TODO: Aggressive NSEC
    msgcachesize=dict(default=4, type='int', choices=[4, 10, 20, 50, 100, 250, 512]),
    outgoing_num_tcp=dict(default=10, type='int', choices=[0, 10, 20, 30, 50]),
    incoming_num_tcp=dict(default=10, type='int', choices=[0, 10, 20, 30, 50]),
    edns_buffer_size=dict(default="auto", type='str', choices=["auto", "512", "1220", "1232", "1432", "1480", "4096"]),
    num_queries_per_thread=dict(default=512, type='int', choices=[512, 1024, 2048]),
    jostle_timeout=dict(default=200, type='int', choices=[100, 200, 500, 1000]),
    cache_max_ttl=dict(default=86400, type='int'),
    cache_min_ttl=dict(default=0, type='int'),
    infra_host_ttl=dict(default=900, type='int', choices=[60, 120, 300, 600, 900]),
    infra_cache_numhosts=dict(default=10000, type='int', choices=[1000, 5000, 10000, 20000, 50000, 100000, 200000]),
    unwanted_reply_threshold=dict(default="disabled", type='str', choices=["disabled", "5000000", "10000000", "20000000", "40000000", "50000000"]),
    log_verbosity=dict(default=1, type='int', choices=[0, 1, 2, 3, 4, 5])
    # TODO: Disable Auto-added Access Control
    # TODO: Disable Auto-added Host Entries
    # TODO: Experimental Bit 0x20 Support
    # TODO: DNS64 Support
)

DNS_RESOLVER_REQUIRED_IF = []


class PFSenseDNSResolverModule(PFSenseModuleBase):
    """ module managing pfsense dns resolver (unbound) """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DNS_RESOLVER_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDNSResolverModule, self).__init__(module, pfsense)
        self.name = "pfsense_dns_resolver"
        self.root_elt = self.pfsense.get_element('unbound')
        self.obj = dict()
        self.interface_elt = None
        self.dynamic = False

        if self.root_elt is None:
            self.root_elt = self.pfsense.new_element('unbound')
            self.pfsense.root.append(self.root_elt)

    def get_interface_by_display_name(self, if_descr: str):
        if if_descr.lower() == "all":
            return "all"
        else:
            return self.pfsense.get_interface_by_display_name(if_descr)

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()

        if params["state"] == "present":

            obj["enable"] = ""
            obj["active_interface"] = ",".join(self.get_interface_by_display_name(x) for x in params["active_interface"])
            obj["outgoing_interface"] = ",".join(self.get_interface_by_display_name(x) for x in params["outgoing_interface"])
            obj["custom_options"] = base64.b64encode(bytes(params['custom_options'], 'utf-8')).decode()
            self._get_ansible_param_bool(obj, "hideidentity", value="")
            self._get_ansible_param_bool(obj, "hideversion", value="")
            self._get_ansible_param_bool(obj, "dnssecstripped", value="")
            self._get_ansible_param(obj, "port")
            self._get_ansible_param(obj, "tlsport")
            if params["sslcert"]:
                obj["sslcertref"] = self.pfsense.find_cert_elt(params["sslcert"]).find("refid").text
            self._get_ansible_param_bool(obj, "forwarding", value="")
            self._get_ansible_param(obj, "system_domain_local_zone_type")
            self._get_ansible_param_bool(obj, "regdhcp", value="")
            self._get_ansible_param_bool(obj, "regdhcpstatic", value="")
            self._get_ansible_param_bool(obj, "regovpnclients", value="")
            self._get_ansible_param_bool(obj, "enablessl", value="")
            self._get_ansible_param_bool(obj, "dnssec", value="")
            self._get_ansible_param_bool(obj, "forward_tls_upstream", value="")
            self._get_ansible_param_bool(obj, "prefetch", value="")
            self._get_ansible_param_bool(obj, "prefetchkey", value="")
            self._get_ansible_param(obj, "msgcachesize")
            self._get_ansible_param(obj, "outgoing_num_tcp")
            self._get_ansible_param(obj, "incoming_num_tcp")
            self._get_ansible_param(obj, "edns_buffer_size")
            self._get_ansible_param(obj, "num_queries_per_thread")
            self._get_ansible_param(obj, "jostle_timeout")
            self._get_ansible_param(obj, "cache_max_ttl")
            self._get_ansible_param(obj, "cache_min_ttl")
            self._get_ansible_param(obj, "infra_host_ttl")
            self._get_ansible_param(obj, "infra_cache_numhosts")
            self._get_ansible_param(obj, "unwanted_reply_threshold")
            self._get_ansible_param(obj, "log_verbosity")
            self._get_ansible_param(obj, "hosts")
            self._get_ansible_param(obj, "domainoverrides")

            if obj["active_interface"] != "all":
                obj["active_interface"] += ",lo0"

            # wrap <item> to all hosts.alias
            for host in obj["hosts"]:
                if host["aliases"]:
                    tmp_aliases = host["aliases"]
                    host["aliases"] = {
                        "item": tmp_aliases
                    }
                else:
                    # Default is an empty element
                    host["aliases"] = ""

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params["sslcert"] and not self.pfsense.find_cert_elt(params["sslcert"]):
            self.module.fail_json(msg=f'sslcert, {params["sslcert"]} is not a valid description of cert')

        for host in params["hosts"]:
            for ipaddr in host["ip"].split(","):
                if not self.pfsense.is_ipv4_address(ipaddr):
                    self.module.fail_json(msg=f'ip, {ipaddr} is not a ipv4 address')

        for domain in params["domainoverrides"]:
            if not self.pfsense.is_ipv4_address(domain["ip"]):
                self.module.fail_json(msg=f'ip, {domain["ip"]} is not a ipv4 address')

        for if_descr in params["active_interface"] + params["outgoing_interface"]:
            if not self.pfsense.is_interface_display_name(if_descr) and if_descr.lower() != "all":
                self.module.fail_json(msg=f'if_descr, {if_descr}, is not exist')

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        return self.root_elt

    def _find_target(self):
        """ find the XML target_elt """
        return self.root_elt

    def _get_params_to_remove(self):
        """ returns the list of params to remove if they are not set """
        if self.params["state"] == "absent":
            return ["enable"]
        else:
            return []

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell('''
require_once("unbound.inc");
require_once("pfsense-utils.inc");
require_once("system.inc");

services_unbound_configure();
system_resolvconf_generate();
system_dhcpleases_configure();
clear_subsystem_dirty("unbound");
''')

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return self.name

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        values += self.format_updated_cli_field(self.obj, before, 'enable', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'active_interface', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'outgoing_interface', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'custom_options', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'hideidentity', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'hideversion', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'dnssecstripped', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'port', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'tlsport', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'sslcertref', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'forwarding', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'system_domain_local_zone_type', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'regdhcp', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'regdhcpstatic', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'prefetch', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'prefetchkey', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'msgcachesize', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'outgoing_num_tcp', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'incoming_num_tcp', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'edns_buffer_size', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'num_queries_per_thread', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'jostle_timeout', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'cache_max_ttl', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'cache_min_ttl', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'infra_host_ttl', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'infra_cache_numhosts', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'unwanted_reply_threshold', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'log_verbosity', add_comma=(values), log_none=False)

        # todo: hosts and domainoverrides is not logged
        return values


def main():
    module = AnsibleModule(
        argument_spec=DNS_RESOLVER_ARGUMENT_SPEC,
        required_if=DNS_RESOLVER_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseDNSResolverModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
