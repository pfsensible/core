#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Chris Liu <chris.liu.hk@icloud.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {"metadata_version": "1.1",
                    "status": ["preview"],
                    "supported_by": "community"}

DOCUMENTATION = """
---
module: pfsense_dns_resolver
version_added: 0.6.0
author: Chris liu (@chris-cyliu), Daniel Huss (@danhuss)
short_description: Manage pfSense DNS resolver (unbound) settings
description:
  - Manage pfSense DNS resolver (unbound) settings
notes:
  - Existing resolver settings are preserved when their parameters are omitted.
  - The module uses its initialization defaults only when the resolver configuration is missing.
  - With O(preserve=false), pass an empty string for O(custom_options)
    or an empty list for O(hosts) or O(domainoverrides) to clear that setting.
options:
  state:
    description: Enable/Disable DNS Resolver
    default: present
    choices: [ "present", "absent" ]
    type: str
  port:
    description: Listen Port
    required: false
    type: int
  enablessl:
    description: Enable SSL/TLS Service
    required: false
    type: bool
  sslcert:
    description: Description of the server certificate to use for SSL/TLS service.
    required: false
    type: str
  tlsport:
    description: SSL/TLS Listen Port
    required: false
    type: int
  active_interface:
    description:
      - Interface IPs used by the DNS Resolver for responding to queries from clients.
      - For Virtual IPs you can specify either the IP, Description, or "IP (Description)".
    required: false
    type: list
    elements: str
  outgoing_interface:
    description:
      - Utilize different network interface(s) that the DNS Resolver will use to send queries to authoritative servers and receive their replies.
      - For Virtual IPs you can specify either the IP, Description, or "IP (Description)".
    required: false
    type: list
    elements: str
  strictout:
    description:
      - Strict Outgoing Network Interface Binding.
      - Do not send recursive queries if none of the Outgoing Network Interfaces are available.
    required: false
    type: bool
    version_added: 0.7.2
  system_domain_local_zone_type:
    description: The local-zone type used for the pfSense system domain.
    required: false
    type: str
    choices: [ "deny", "refuse", "static", "transparent", "typetransparent", "redirect", "inform", "inform_deny", "nodefault" ]
  dnssec:
    description: Enable DNSSEC Support
    required: false
    type: bool
  forwarding:
    description: DNS Query Forwarding.
    required: false
    type: bool
  forward_tls_upstream:
    description: Use SSL/TLS for DNS Query Forwarding.
    required: false
    type: bool
  regdhcp:
    description: Register DHCP leases in the DNS Resolver
    required: false
    type: bool
  regdhcpstatic:
    description: Register DHCP static mappings in the DNS Resolver
    required: false
    type: bool
  regovpnclients:
    description: Register OpenVPN clients in the DNS Resolver
    required: false
    type: bool
  custom_options:
    description: additional configuration parameters
    required: false
    type: str
  hosts:
    description: Individual hosts for which the resolver's standard DNS lookup should be overridden.
    required: false
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
        default: false
        type: bool
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
    type: bool
  hideversion:
    description: version.server and version.bind queries are refused.
    required: false
    type: bool
  prefetch:
    description: Message cache elements are prefetched before they expire to help keep the cache up to date.
    required: false
    type: bool
  prefetchkey:
    description: DNSKEYs are fetched earlier in the validation process when a Delegation signer is encountered.
    required: false
    type: bool
  dnssecstripped:
    description: If enabled, DNSSEC data is required for trust-anchored zones.
    required: false
    type: bool
  msgcachesize:
    description: Message cache size in MB
    required: false
    choices: [ 4, 10, 20, 50, 100, 250, 512 ]
    type: int
  outgoing_num_tcp:
    description: Number of outgoing TCP buffers to allocate per thread.
    required: false
    choices: [ 0, 10, 20, 30, 50 ]
    type: int
  incoming_num_tcp:
    description: Number of incoming TCP buffers to allocate per thread.
    required: false
    choices: [ 0, 10, 20, 30, 50 ]
    type: int
  edns_buffer_size:
    description: Number of bytes to advertise as the EDNS reassembly buffer size.
    required: false
    choices: [ "auto", "512", "1220", "1232", "1432", "1480", "4096" ]
    type: str
  num_queries_per_thread:
    description: Number of queries that every thread will service simultaneously.
    required: false
    choices: [ 512, 1024, 2048 ]
    type: int
  jostle_timeout:
    description: This timeout (in milliseconds) is used for when the server is very busy.
    required: false
    choices: [ 100, 200, 500, 1000 ]
    type: int
  cache_max_ttl:
    description: The Maximum Time to Live (in seconds) for RRsets and messages in the cache.
    required: false
    type: int
  cache_min_ttl:
    description: The Minimum Time to Live (in seconds) for RRsets and messages in the cache.
    required: false
    type: int
  infra_host_ttl:
    description: Time to Live, in seconds, for entries in the infrastructure host cache.
    required: false
    choices: [ 60, 120, 300, 600, 900 ]
    type: int
  infra_cache_numhosts:
    description: Number of infrastructure hosts for which information is cached.
    required: false
    choices: [ 1000, 5000, 10000, 20000, 50000, 100000, 200000 ]
    type: int
  unwanted_reply_threshold:
    description: If enabled, a total number of unwanted replies is kept track of in every thread.
    required: false
    choices: [ "disabled", "5000000", "10000000", "20000000", "40000000", "50000000" ]
    type: str
  log_verbosity:
    description: The level of detail to be logged.
    required: false
    choices: [ 0, 1, 2, 3, 4, 5 ]
    type: int
  preserve:
    description: Preserve the current DNS entries instead of overriding them.
    required: false
    default: false
    type: bool
    version_added: 0.7.2
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
import re

# TODO: access control is not done here
# TODO: alias for DNS record

DNS_RESOLVER_DOMAIN_OVERRIDE_SPEC = dict(
    domain=dict(required=True, type="str"),
    ip=dict(required=True, type="str"),
    descr=dict(type="str"),
    tls_hostname=dict(default="", type="str"),
    forward_tls_upstream=dict(default=False, type="bool"),
)

DNS_RESOLVER_HOST_ALIAS_SPEC = dict(
    host=dict(required=True, type="str"),
    domain=dict(required=True, type="str"),
    description=dict(required=True, type="str"),
)

DNS_RESOLVER_HOST_SPEC = dict(
    host=dict(required=True, type="str"),
    domain=dict(required=True, type="str"),
    ip=dict(required=True, type="str"),
    descr=dict(default="", type="str"),
    aliases=dict(default=[], type="list", elements="dict", options=DNS_RESOLVER_HOST_ALIAS_SPEC),
)

DNS_RESOLVER_ARGUMENT_SPEC = dict(
    state=dict(default="present", choices=["present", "absent"]),

    # General Settings
    port=dict(type="int"),
    enablessl=dict(type="bool"),
    sslcert=dict(type="str"),
    tlsport=dict(type="int"),
    active_interface=dict(type="list", elements="str"),
    outgoing_interface=dict(type="list", elements="str"),
    strictout=dict(type="bool"),
    system_domain_local_zone_type=dict(
        choices=["deny", "refuse", "static", "transparent", "typetransparent", "redirect", "inform", "inform_deny", "nodefault"],
    ),
    dnssec=dict(type="bool"),
    # TODO: Python Module: Enable the Python Module. These 3 options omited when disabled
    # python=dict(default=False, type='bool'),
    # python_order=dict(default="pre_validator", type='str', choices=["pre_validator", "post_validator"]),
    # python_script=dict(default="", type='str'), #Not sure what this is or how to handle it.
    forwarding=dict(type="bool"),
    forward_tls_upstream=dict(type="bool"),
    regdhcp=dict(type="bool"),
    regdhcpstatic=dict(type="bool"),
    regovpnclients=dict(type="bool"),
    custom_options=dict(type="str"),
    hosts=dict(type="list", elements="dict", options=DNS_RESOLVER_HOST_SPEC),
    domainoverrides=dict(type="list", elements="dict", options=DNS_RESOLVER_DOMAIN_OVERRIDE_SPEC),
    # Advanced Settings
    hideidentity=dict(type="bool"),
    hideversion=dict(type="bool"),
    # TODO: Query Name Minimization
    # TODO: Strict Query Name Minimization
    prefetch=dict(type="bool"),
    prefetchkey=dict(type="bool"),
    dnssecstripped=dict(type="bool"),
    # TODO: Serve Expired
    # TODO: Aggressive NSEC
    msgcachesize=dict(type="int", choices=[4, 10, 20, 50, 100, 250, 512]),
    outgoing_num_tcp=dict(type="int", choices=[0, 10, 20, 30, 50]),
    incoming_num_tcp=dict(type="int", choices=[0, 10, 20, 30, 50]),
    edns_buffer_size=dict(type="str", choices=["auto", "512", "1220", "1232", "1432", "1480", "4096"]),
    num_queries_per_thread=dict(type="int", choices=[512, 1024, 2048]),
    jostle_timeout=dict(type="int", choices=[100, 200, 500, 1000]),
    cache_max_ttl=dict(type="int"),
    cache_min_ttl=dict(type="int"),
    infra_host_ttl=dict(type="int", choices=[60, 120, 300, 600, 900]),
    infra_cache_numhosts=dict(type="int", choices=[1000, 5000, 10000, 20000, 50000, 100000, 200000]),
    unwanted_reply_threshold=dict(type="str", choices=["disabled", "5000000", "10000000", "20000000", "40000000", "50000000"]),
    log_verbosity=dict(type="int", choices=[0, 1, 2, 3, 4, 5]),
    preserve=dict(default=False, type="bool"),
    # TODO: Disable Auto-added Access Control
    # TODO: Disable Auto-added Host Entries
    # TODO: Experimental Bit 0x20 Support
    # TODO: DNS64 Support
)

DNS_RESOLVER_CREATE_DEFAULT = dict(
    active_interface="all",
    outgoing_interface="all",
    custom_options="",
    hideidentity="",
    hideversion="",
    dnssecstripped="",
    system_domain_local_zone_type="transparent",
    dnssec="",
    msgcachesize="4",
    outgoing_num_tcp="10",
    incoming_num_tcp="10",
    edns_buffer_size="auto",
    num_queries_per_thread="512",
    jostle_timeout="200",
    cache_max_ttl="86400",
    cache_min_ttl="0",
    infra_host_ttl="900",
    infra_cache_numhosts="10000",
    unwanted_reply_threshold="disabled",
    log_verbosity="1",
)

DNS_RESOLVER_BOOL_PARAMS = (
    "hideidentity", "hideversion", "dnssecstripped", "forwarding", "regdhcp", "regdhcpstatic", "regovpnclients", "enablessl", "dnssec",
    "forward_tls_upstream", "prefetch", "prefetchkey", "strictout",
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
        super(PFSenseDNSResolverModule, self).__init__(module, pfsense, name="pfsense_dns_resolver", root="pfsense", node="unbound")

        cmd = ('require_once("interfaces.inc");;'
               '$iflist = get_possible_listen_ips(true);'
               'echo json_encode($iflist);')
        self.iflist = self.pfsense.php(cmd)

    def _get_interface_name(self, iface: str):
        ifacelow = iface.lower()
        if ifacelow == "all":
            return "all"
        else:
            for iname, idescr in self.iflist.items():
                if ifacelow == iname.lower() or ifacelow == idescr.lower():
                    return iname
                # Virtual IPs are listed in the format "IP" or "IP (Description)" - allow specifying either IP or Description
                if re.match(f"{re.escape(ifacelow)}(?: \\(|$)", idescr.lower()) or re.search(f" \\({re.escape(ifacelow)}\\)$", idescr.lower()):
                    return iname
        self.module.fail_json(msg=f"Invalid interface '{iface}'")

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        if params["state"] == "absent":
            return {}

        target = self._find_target()
        obj = DNS_RESOLVER_CREATE_DEFAULT.copy() if target is None else {}
        obj["enable"] = ""
        for param in ("active_interface", "outgoing_interface"):
            if params[param] is not None:
                obj[param] = ",".join(self._get_interface_name(iface) for iface in params[param])

        if params["custom_options"] is not None:
            custom_options = params["custom_options"]
            existing_options = target.findtext("custom_options") if params["preserve"] and target is not None else None
            if existing_options and custom_options:
                existing_lines = [line.strip() for line in base64.b64decode(existing_options).decode("utf-8").strip().split("\n")]
                new_lines = [line.strip() for line in custom_options.strip().split("\n")]
                additions = [line for line in new_lines if "view:" in line or "server:" in line or line not in existing_lines]
                custom_options = "\n".join(existing_lines + additions)
            if custom_options or not existing_options:
                obj["custom_options"] = base64.b64encode(custom_options.encode("utf-8")).decode("ascii")

        for param in DNS_RESOLVER_BOOL_PARAMS:
            self._get_ansible_param_bool(obj, param, value="")
        for param in ("port", "tlsport", "system_domain_local_zone_type", "msgcachesize", "outgoing_num_tcp", "incoming_num_tcp",
                      "edns_buffer_size", "num_queries_per_thread", "jostle_timeout", "cache_max_ttl", "cache_min_ttl", "infra_host_ttl",
                      "infra_cache_numhosts", "unwanted_reply_threshold", "log_verbosity"):
            self._get_ansible_param(obj, param)
        if params["sslcert"]:
            obj["sslcertref"] = self.pfsense.find_cert_elt(params["sslcert"]).find("refid").text

        if params["hosts"] is not None:
            obj["hosts"] = self._existing_overrides(target, "hosts")
            for host_params in params["hosts"]:
                new_host = host_params.copy()
                # Set an empty alias element to remove any stale alias children.
                new_host["aliases"] = {"item": new_host["aliases"]} if new_host["aliases"] else ""

                existing_host_index = self._find_host_index(obj, new_host)
                if existing_host_index is not None:
                    obj["hosts"][existing_host_index] = new_host
                else:
                    obj["hosts"].append(new_host)

        if params["domainoverrides"] is not None:
            obj["domainoverrides"] = self._existing_overrides(target, "domainoverrides")
            for override_params in params["domainoverrides"]:
                override = override_params.copy()
                self._get_ansible_param_bool(override, "forward_tls_upstream", value="", params=override)
                obj["domainoverrides"].append(override)

        if ("active_interface" in obj and self.pfsense.config_get_path("system/dnslocalhost") != "remote" and
                "lo0" not in obj["active_interface"] and "all" not in obj["active_interface"]):
            self.module.fail_json(msg="This system is configured to use the DNS Resolver as its DNS server, so Localhost or All must be selected in"
                                      " active_interface.")

        return obj

    def _existing_overrides(self, target, key):
        if self.params["preserve"] and target is not None:
            return [self.pfsense.element_to_dict(elt) for elt in target.findall(key)]
        return []

    def _find_host_index(self, obj, new_host):
        for index, nested_dict in enumerate(obj["hosts"]):
            existing_host = f"{nested_dict.get('host')}.{nested_dict.get('domain')}"
            new_host_fqdn = f"{new_host.get('host')}.{new_host.get('domain')}"
            if existing_host == new_host_fqdn:
                return index
        return None

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params["sslcert"] and not self.pfsense.find_cert_elt(params["sslcert"]):
            self.module.fail_json(msg=f'sslcert, {params["sslcert"]} is not a valid description of cert')

        for host in params["hosts"] or []:
            for ipaddr in host["ip"].split(","):
                if not self.pfsense.is_ipv4_address(ipaddr) and not self.pfsense.is_ipv6_address(ipaddr):
                    self.module.fail_json(msg=f"ip, {ipaddr} is not a ipv4/ipv6 address")

        if params["domainoverrides"] is not None:
            for domain in params["domainoverrides"]:
                if not self.pfsense.is_ipv4_address(domain["ip"]) and not self.pfsense.is_ipv6_address(domain["ip"]):
                    self.module.fail_json(msg=f'ip, {domain["ip"]} is not a ipv4/ipv6 address')

    ##############################
    # XML processing
    #
    def _find_target(self):
        """ find the XML target_elt """
        return self.pfsense.get_element(self.node, root_elt=self.root_elt)

    def _get_params_to_remove(self):
        """ return boolean flags explicitly set to false """
        return [param for param in DNS_RESOLVER_BOOL_PARAMS if self.params[param] is False]

    def _remove_target_elt(self):
        """ disable the resolver: target_elt is the unbound root, so only clear its enable flag """
        if self.pfsense.remove_deleted_param_from_elt(self.target_elt, "enable", {}):
            self.result["changed"] = True

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell("""
require_once("unbound.inc");
require_once("pfsense-utils.inc");
require_once("system.inc");

services_unbound_configure();
system_resolvconf_generate();
system_dhcpleases_configure();
clear_subsystem_dirty("unbound");
""")

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return self.name

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        after = self.diff["after"]
        previous = before if before is not None else {}
        values = ""

        values += self.format_updated_cli_field(after, previous, "enable", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "active_interface", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "outgoing_interface", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "custom_options", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "hideidentity", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "hideversion", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "dnssecstripped", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "port", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "tlsport", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "sslcertref", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "forwarding", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "strictout", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "system_domain_local_zone_type", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "regdhcp", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "regdhcpstatic", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "prefetch", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "prefetchkey", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "msgcachesize", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "outgoing_num_tcp", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "incoming_num_tcp", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "edns_buffer_size", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "num_queries_per_thread", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "jostle_timeout", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "cache_max_ttl", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "cache_min_ttl", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "infra_host_ttl", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "infra_cache_numhosts", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "unwanted_reply_threshold", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(after, previous, "log_verbosity", add_comma=(values), log_none=False)

        # todo: hosts and domainoverrides is not logged
        return " set " + values if before is None else values


def main():
    module = AnsibleModule(
        argument_spec=DNS_RESOLVER_ARGUMENT_SPEC,
        required_if=DNS_RESOLVER_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseDNSResolverModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
