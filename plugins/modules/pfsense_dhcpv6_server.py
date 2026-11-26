#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Romain Tiennot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_dhcpv6_server

short_description: Manage pfSense DHCPv6 servers

version_added: "0.8.0"

description:
  - Manage the DHCPv6 server of an interface (Services > DHCPv6 Server), its main settings. Its pools, static mappings, dynamic DNS,
    network booting and custom options are left as they are.
  - Omitted options preserve existing settings.
  - As the Apply button of the page does, the DHCP servers are reconfigured after a change.

notes:
  - pfSense stores the Router Advertisement settings of an interface with its DHCPv6 server. O(state=absent) removes them too.

options:
  interface:
    description: Interface of the server, by its name (V(lan), V(opt1)...), its port or its description.
    type: str
    required: true
  state:
    description:
      - V(absent) removes all the DHCPv6 and Router Advertisement settings of the interface.
    type: str
    choices: [present, absent]
    default: present
  enable:
    description:
      - Enable the DHCPv6 server on the interface.
      - Enabling it needs a range, unless the Router Advertisement mode of the interface is Stateless DHCP.
    type: bool
  range_from:
    description:
      - First address of the range. Given with O(range_to).
      - On an interface that tracks another one (Track Interface), the suffix of the address, with the upper 64 bits zero (V(::1000)).
        Otherwise an address of the interface's subnet when its address is static.
    type: str
  range_to:
    description: Last address of the range. Given with O(range_from).
    type: str
  prefixrange_from:
    description: First prefix of the prefix delegation range. Given with O(prefixrange_to).
    type: str
  prefixrange_to:
    description: Last prefix of the prefix delegation range. Given with O(prefixrange_from).
    type: str
  prefixrange_length:
    description: Length of the delegated prefixes.
    type: int
    choices: [48, 52, 56, 59, 60, 61, 62, 63, 64]
  defaultleasetime:
    description: Default lease time, in seconds, 60 or more.
    type: int
  maxleasetime:
    description: Maximum lease time, in seconds, 60 or more and at least the default lease time.
    type: int
  dnsserver:
    description:
      - DNS servers given to the clients, up to 4 IPv6 addresses.
      - An empty list removes them, and the server gives the firewall's own.
    type: list
    elements: str
  domain:
    description: Domain name given to the clients.
    type: str
  domainsearchlist:
    description:
      - Domain search list given to the clients.
      - An empty list removes it.
    type: list
    elements: str
  ntpserver:
    description:
      - NTP servers given to the clients, up to 4 IPv6 addresses.
      - An empty list removes them.
    type: list
    elements: str

author: Romain Tiennot (@RomainTie)
"""

EXAMPLES = r"""
- name: Serve addresses on the LAN, which tracks the WAN's prefix
  pfsensible.core.pfsense_dhcpv6_server:
    interface: lan
    enable: true
    range_from: "::1000"
    range_to: "::2000"
    dnsserver:
      - 2001:db8::53

- name: Remove the DHCPv6 and Router Advertisement settings of opt1
  pfsensible.core.pfsense_dhcpv6_server:
    interface: opt1
    state: absent
"""

RETURN = r"""
commands:
    description: Pseudo-CLI commands describing configuration changes.
    returned: always
    type: list
    elements: str
    sample: ["update dhcpv6_server 'lan' set range_from='::1000', range_to='::2000'"]
"""

import re
from ipaddress import IPv6Address, IPv6Network, ip_network

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

DHCPV6_SERVER_ARGUMENT_SPEC = dict(
    interface=dict(type="str", required=True),
    state=dict(type="str", choices=["present", "absent"], default="present"),
    enable=dict(type="bool"),
    range_from=dict(type="str"),
    range_to=dict(type="str"),
    prefixrange_from=dict(type="str"),
    prefixrange_to=dict(type="str"),
    prefixrange_length=dict(type="int", choices=[48, 52, 56, 59, 60, 61, 62, 63, 64]),
    defaultleasetime=dict(type="int"),
    maxleasetime=dict(type="int"),
    dnsserver=dict(type="list", elements="str"),
    domain=dict(type="str"),
    domainsearchlist=dict(type="list", elements="str"),
    ntpserver=dict(type="list", elements="str"),
)

# The options, in the order of the page, and where they are stored
FIELDS = [
    ("enable", "enable"), ("range_from", "range/from"), ("range_to", "range/to"), ("prefixrange_from", "prefixrange/from"),
    ("prefixrange_to", "prefixrange/to"), ("prefixrange_length", "prefixrange/prefixlength"), ("defaultleasetime", "defaultleasetime"),
    ("maxleasetime", "maxleasetime"), ("dnsserver", "dnsserver"), ("domain", "domain"), ("domainsearchlist", "domainsearchlist"),
    ("ntpserver", "ntpserver"),
]

# is_domain() of /etc/inc/util.inc
DOMAIN_RE = re.compile(r"^(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$", re.IGNORECASE)

REDACTED = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"

# What the Apply button of the page does for the DHCPv6 server
DHCPV6_SERVER_PHP_COMMAND = """
require_once("util.inc");
require_once("services.inc");
services_dhcpd_configure("inet6");
"""


def as_list(value):
    """ a repeated element as a list """
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


class PFSenseDHCPv6ServerModule(PFSenseModuleBase):
    """ module managing pfSense DHCPv6 servers """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DHCPV6_SERVER_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseDHCPv6ServerModule, self).__init__(module, pfsense, name="pfsense_dhcpv6_server", update_php=DHCPV6_SERVER_PHP_COMMAND)
        self.root_elt = self.pfsense.get_element("dhcpdv6", create_node=True)
        self.target = None
        self.current = dict()

    ##############################
    # params processing
    #
    def _get_logical_interface(self, interface):
        """ the name of the interface given by its name, port or description """
        for iface in self.pfsense.interfaces:
            if iface.tag.lower() == interface.lower():
                return iface.tag
            for field in ["if", "descr"]:
                value = iface.findtext(field)
                if value is not None and value.strip().lower() == interface.lower():
                    return iface.tag
        return None

    def _wanted(self, option, field):
        """ the value the option will have: the parameter when given, else the stored one """
        value = self.params.get(option)
        if value is None:
            current = self.current
            for part in field.split("/"):
                current = current.get(part) if isinstance(current, dict) else None
            return current
        return value

    def _fail(self, msg):
        self.module.fail_json(msg=msg)

    def _validate_range(self, interface_elt):
        params = self.params
        if (params.get("range_from") is None) != (params.get("range_to") is None):
            self._fail("range_from and range_to must be given together")
        if params.get("range_from") is None:
            return

        addresses = []
        for option in ["range_from", "range_to"]:
            if not self.pfsense.is_ipv6_address(params[option]):
                self._fail("{0} must be a valid IPv6 address".format(option))
            addresses.append(IPv6Address(params[option]))

        ipaddrv6 = interface_elt.findtext("ipaddrv6") or ""
        if ipaddrv6 == "track6":
            # The suffix of the address in the tracked prefix
            for option, address in zip(["range_from", "range_to"], addresses):
                if address not in IPv6Network("::/64"):
                    self._fail("{0} must be a suffix, with the upper 64 bits zero (::1000), on an interface that tracks another one".format(option))
        elif self.pfsense.is_ipv6_address(ipaddrv6) and interface_elt.findtext("subnetv6"):
            network = ip_network(u"{0}/{1}".format(ipaddrv6, interface_elt.findtext("subnetv6")), strict=False)
            if addresses[0] not in network or addresses[1] not in network:
                self._fail("The range must lie in the subnet of {0} ({1})".format(params["interface"], network))

        if addresses[0] > addresses[1]:
            self._fail("range_from must not be after range_to")

    def _validate_prefixrange(self):
        params = self.params
        if (params.get("prefixrange_from") is None) != (params.get("prefixrange_to") is None):
            self._fail("prefixrange_from and prefixrange_to must be given together")
        length = self._wanted("prefixrange_length", "prefixrange/prefixlength")
        for option in ["prefixrange_from", "prefixrange_to"]:
            if params.get(option) is None:
                continue
            if not self.pfsense.is_ipv6_address(params[option]):
                self._fail("{0} must be a valid IPv6 prefix".format(option))
            if length and str(IPv6Network(u"{0}/{1}".format(params[option], length), strict=False).network_address) != str(IPv6Address(params[option])):
                self._fail("{0} must be the first address of a /{1} prefix".format(option, length))

    def _validate_params(self):
        """ do the checks of the web GUI """
        params = self.params

        self.target = self._get_logical_interface(params["interface"])
        if self.target is None:
            self._fail("The specified interface {0} is not a valid logical interface or cannot be mapped to one".format(params["interface"]))
        target_elt = self.pfsense.get_element(self.target, root_elt=self.root_elt)
        self.current = self.pfsense.element_to_dict(target_elt) if target_elt is not None else dict()
        if params["state"] == "absent":
            return

        if self.target.lower() == "wan":
            self._fail("The DHCPv6 server cannot be configured on the WAN interface")

        self._validate_range(self.pfsense.get_element("interfaces/" + self.target))
        self._validate_prefixrange()

        for option in ["defaultleasetime", "maxleasetime"]:
            if params.get(option) is not None and params[option] < 60:
                self._fail("{0} must be at least 60 seconds".format(option))
        default, maximum = self._wanted("defaultleasetime", "defaultleasetime"), self._wanted("maxleasetime", "maxleasetime")
        if default and maximum and int(maximum) < int(default):
            self._fail("maxleasetime must be at least defaultleasetime")

        for option in ["dnsserver", "ntpserver"]:
            values = params.get(option) or []
            if len(values) > 4:
                self._fail("{0} takes up to 4 addresses".format(option))
            for value in values:
                if not self.pfsense.is_ipv6_address(value):
                    self._fail("{0} must contain IPv6 addresses: {1} is not one".format(option, value))

        for domain in ([params["domain"]] if params.get("domain") else []) + (params.get("domainsearchlist") or []):
            if not DOMAIN_RE.match(domain):
                self._fail("{0} is not a valid domain name".format(domain))

        enabled = params["enable"] if params.get("enable") is not None else "enable" in self.current
        if enabled and not self._wanted("range_from", "range/from") and self.current.get("ramode") != "stateless_dhcp":
            self._fail("A range is required to enable the DHCPv6 server, unless the Router Advertisement mode is Stateless DHCP")

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params
        obj = dict()
        if params["state"] == "absent":
            return obj

        if params.get("enable"):
            obj["enable"] = ""
        if params.get("range_from") is not None:
            obj["range"] = dict(self.current.get("range") or {}, **{"from": params["range_from"], "to": params["range_to"]})
        if params.get("prefixrange_from") is not None or params.get("prefixrange_length") is not None:
            prefixrange = dict(self.current.get("prefixrange") or {})
            if params.get("prefixrange_from") is not None:
                prefixrange.update({"from": params["prefixrange_from"], "to": params["prefixrange_to"]})
            if params.get("prefixrange_length") is not None:
                prefixrange["prefixlength"] = str(params["prefixrange_length"])
            obj["prefixrange"] = prefixrange
        for option in ["defaultleasetime", "maxleasetime"]:
            if params.get(option) is not None:
                obj[option] = str(params[option])
        if params.get("domain") is not None:
            obj["domain"] = params["domain"]
        if params.get("domainsearchlist") is not None:
            obj["domainsearchlist"] = ";".join(params["domainsearchlist"])
        for option in ["dnsserver", "ntpserver"]:
            if params.get(option):
                obj[option] = list(params[option])
        return obj

    def _get_params_to_remove(self):
        """ the fields removed by the task """
        to_remove = []
        if self.params.get("enable") is False:
            to_remove.append("enable")
        if self.params.get("domainsearchlist") == []:
            to_remove.append("domainsearchlist")
        return to_remove

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element(self.target)

    def _find_target(self):
        """ find the XML target_elt """
        return self.pfsense.get_element(self.target, root_elt=self.root_elt)

    def _remove_deleted_params(self):
        """ remove the fields removed by the task, and every element of a list set to empty """
        changed = super(PFSenseDHCPv6ServerModule, self)._remove_deleted_params()
        for option in ["dnsserver", "ntpserver"]:
            if self.params.get(option) == []:
                for elt in self.target_elt.findall(option):
                    self.target_elt.remove(elt)
                    changed = True
        return changed

    def _pre_remove_target_elt(self):
        self.diff["before"] = self.pfsense.element_to_dict(self.target_elt)
        self.diff["after"] = dict()

    def _run_post(self):
        # The diff holds the whole section: hide the dynamic DNS key
        for snapshot in self.diff.values():
            if isinstance(snapshot, dict) and snapshot.get("ddnsdomainkey"):
                snapshot["ddnsdomainkey"] = REDACTED

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}'".format(self.target)

    @staticmethod
    def _view(values):
        """ the options of a server's fields, as the task gives them """
        view = dict()
        for option, field in FIELDS:
            value = values
            for part in field.split("/"):
                value = value.get(part) if isinstance(value, dict) else None
            if option == "enable":
                view[option] = "True" if value is not None else "False"
            elif option in ["dnsserver", "ntpserver"]:
                view[option] = "'{0}'".format(" ".join(as_list(value))) if as_list(value) else "none"
            else:
                view[option] = "'{0}'".format(value) if value not in (None, "") else "none"
        return view

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters """
        after = self._view(self.diff["after"] if before is not None else self.obj)
        if before is None:
            return "".join(", {0}={1}".format(option, after[option]) for option, dummy in FIELDS if after[option] not in ("none", "False"))
        before = self._view(before)
        return ", ".join("{0}={1}".format(option, after[option]) for option, dummy in FIELDS if after[option] != before[option])


def main():
    module = AnsibleModule(
        argument_spec=DHCPV6_SERVER_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseDHCPv6ServerModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
