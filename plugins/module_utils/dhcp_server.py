# -*- coding: utf-8 -*-

# Copyright: (c) 2024, David Rosado <davidrosza0@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ipaddress import ip_address, ip_network
import re

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import (
    PFSenseModuleBase,
)

DHCPSERVER_ARGUMENT_SPEC = dict(
    state=dict(type="str", default="present", choices=["present", "absent"]),
    interface=dict(required=True, type="str"),
    enable=dict(type="bool", default=True),
    range_from=dict(type="str"),
    range_to=dict(type="str"),
    failover_peerip=dict(type="str"),
    defaultleasetime=dict(type="int"),
    maxleasetime=dict(type="int"),
    netmask=dict(type="str"),
    gateway=dict(type="str"),
    domain=dict(type="str"),
    domainsearchlist=dict(type="str"),
    ddnsdomain=dict(type="str"),
    ddnsdomainprimary=dict(type="str"),
    ddnsdomainkeyname=dict(type="str", no_log=False),
    ddnsdomainkeyalgorithm=dict(
        type="str",
        default="hmac-md5",
        choices=[
            "hmac-md5",
            "hmac-sha1",
            "hmac-sha224",
            "hmac-sha256",
            "hmac-sha384",
            "hmac-sha512",
        ],
    ),
    ddnsdomainkey=dict(type="str", no_log=True),
    mac_allow=dict(type="list", elements="str"),
    mac_deny=dict(type="list", elements="str"),
    ddnsclientupdates=dict(
        type="str", default="allow", choices=["allow", "deny", "ignore"]
    ),
    tftp=dict(type="str"),
    ldap=dict(type="str"),
    nextserver=dict(type="str"),
    filename=dict(type="str"),
    filename32=dict(type="str"),
    filename64=dict(type="str"),
    rootpath=dict(type="str"),
    numberoptions=dict(type="str"),
    winsserver=dict(type="list", elements="str"),
    dnsserver=dict(type="list", elements="str"),
    ntpserver=dict(type="list", elements="str"),
    ignorebootp=dict(type="bool"),
    denyunknown=dict(type="str", choices=["disabled", "enabled", "class"]),
    nonak=dict(type="bool"),
    ignoreclientuids=dict(type="bool"),
    staticarp=dict(type="bool"),
    dhcpinlocaltime=dict(type="bool"),
    statsgraph=dict(type="bool"),
    disablepingcheck=dict(type="bool"),
)


class PFSenseDHCPServerModule(PFSenseModuleBase):
    """module managing pfsense DHCP server settings"""

    @staticmethod
    def get_argument_spec():
        """return argument spec"""
        return DHCPSERVER_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDHCPServerModule, self).__init__(module, pfsense)
        self.name = "pfsense_dhcp_server"
        self.obj = dict()

        self.root_elt = self.pfsense.get_element("dhcpd", create_node=True)
        self.target = None
        self.network = None

    ##############################
    # params processing
    #
    def _get_logical_interface(self, interface):
        """Find the logical interface name"""
        for iface in self.pfsense.interfaces:
            # Check if it matches the logical name (e.g., 'lan', 'wan', 'opt1')
            if iface.tag.lower() == interface.lower():
                return iface.tag

            # Check if it matches the physical interface name (e.g., 'em0', 'igb0')
            if_elt = iface.find("if")
            if if_elt is not None and if_elt.text.strip().lower() == interface.lower():
                return iface.tag

            # Check if it matches the interface description
            descr_elt = iface.find("descr")
            if (
                descr_elt is not None
                and descr_elt.text.strip().lower() == interface.lower()
            ):
                return iface.tag

        return None

    def _is_valid_netif(self, netif):
        for nic in self.pfsense.interfaces:
            if nic.tag == netif:
                if nic.find("ipaddr") is not None:
                    ipaddr = nic.find("ipaddr").text
                    if ipaddr is not None:
                        if nic.find("subnet") is not None:
                            subnet = int(nic.find("subnet").text)
                            if subnet < 31:
                                self.network = ip_network(
                                    "{0}/{1}".format(ipaddr, subnet), strict=False
                                )
                                return True
        return False

    def _is_valid_macaddr(self, macaddr):
        return bool(
            re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", macaddr, re.I)
        )

    def _params_to_obj(self):
        """return a dict from module params"""
        params = self.params

        obj = dict()
        self.obj = obj

        if params["state"] == "present":
            self._get_ansible_param(obj, "range", force_value={}, force=True)
            self._get_ansible_param(
                obj["range"], "range_from", fname="from", force=True
            )
            self._get_ansible_param(obj["range"], "range_to", fname="to", force=True)

            # Forced options
            for option in [
                "failover_peerip",
                "defaultleasetime",
                "maxleasetime",
                "netmask",
                "gateway",
                "domain",
                "domainsearchlist",
                "ddnsdomain",
                "ddnsdomainprimary",
                "ddnsdomainkeyname",
                "ddnsdomainkeyalgorithm",
                "ddnsdomainkey",
                "mac_allow",
                "mac_deny",
                "ddnsclientupdates",
                "tftp",
                "ldap",
                "nextserver",
                "filename",
                "filename32",
                "filename64",
                "rootpath",
                "numberoptions",
            ]:
                self._get_ansible_param(obj, option, force=True)

            for option in ["mac_allow", "mac_deny"]:
                if params[option] is None:
                    params[option] = ""
                self._get_ansible_param(obj, ",".join(params[option]))

            # Non-forced options
            for option in ["winsserver", "dnsserver", "ntpserver"]:
                self._get_ansible_param(obj, option)

            for option in [
                "enable",
                "ignorebootp",
                "nonak",
                "ignoreclientuids",
                "staticarp",
                "disablepingcheck",
            ]:
                self._get_ansible_param_bool(obj, option, value="")

            for option in ["dhcpinlocaltime", "statsgraph"]:
                self._get_ansible_param_bool(obj, option, value="yes")

            self._get_ansible_param(obj, "denyunknown")
            if obj.get("denyunknown") == "disabled":
                del obj["denyunknown"]

            # Defaulted options
            self._get_ansible_param(
                obj, "ddnsdomainkeyalgorithm", force_value="hmac-md5", force=True
            )

        return obj

    def _validate_params(self):
        """do some extra checks on input parameters"""
        params = self.params

        self.target = self._get_logical_interface(params["interface"])
        if self.target is None or self.target.lower() == "wan":
            self.module.fail_json(
                msg=f"The specified interface {params['interface']} is not a valid logical interface or cannot be mapped to one"
            )

        if not self._is_valid_netif(self.target):
            self.module.fail_json(
                msg=f"The specified interface {params['interface']} is not a valid logical interface"
            )

        if params["state"] == "present" and params["enable"]:
            if params.get("range_from") is None or params.get("range_to") is None:
                self.module.fail_json(
                    msg=f"The specified interface {params['interface']}'requires an IP range"
                )

            if not self.pfsense.is_ipv4_address(params["range_from"]):
                self.module.fail_json(
                    msg="The 'range_from' address is not a valid IPv4 address"
                )
            if not self.pfsense.is_ipv4_address(params["range_to"]):
                self.module.fail_json(
                    msg="The 'range_to' address is not a valid IPv4 address"
                )

            if (
                ip_address(params["range_from"]) not in self.network
                or ip_address(params["range_to"]) not in self.network
            ):
                self.module.fail_json(
                    msg=f"The IP address must lie in the {params['interface']} subnet"
                )

            if ip_address(params["range_from"]) >= ip_address(params["range_to"]):
                self.module.fail_json(
                    msg=f"The interface {params['interface']} must have a valid IP range pool"
                )

            if params.get("gateway"):
                if not self.pfsense.is_ipv4_address(params["gateway"]):
                    self.module.fail_json(
                        msg="The 'gateway' is not a valid IPv4 address"
                    )

            if params.get("mac_allow"):
                for macaddr in params["mac_allow"]:
                    is_valid = self._is_valid_macaddr(macaddr)
                    if not is_valid:
                        self.module.fail_json(
                            msg=f"The MAC address {macaddr} is invalid"
                        )

            if params.get("mac_deny"):
                for macaddr in params["mac_deny"]:
                    is_valid = self._is_valid_macaddr(macaddr)
                    if not is_valid:
                        self.module.fail_json(
                            msg=f"The MAC address {macaddr} is invalid"
                        )

            if params.get("denyunknown") not in [None, "disabled", "enabled", "class"]:
                self.module.fail_json(
                    msg=f"The option {params['denyunknown']} is invalid, use 'disabled', 'enabled' or 'class'"
                )

    ##############################
    # XML processing
    #
    def _get_params_to_remove(self):
        """returns the list of params to remove if they are not set"""
        params = [
            "enable",
            "ignorebootp",
            "nonak",
            "ignoreclientuids",
            "staticarp",
            "disablepingcheck",
            "dhcpinlocaltime",
            "statsgraph",
        ]
        if self.params.get("denyunknown") == "disabled":
            params.append("denyunknown")
        return params

    def _create_target(self):
        """create the XML target_elt"""
        return self.pfsense.new_element(self.target)

    def _find_target(self):
        """find the XML target_elt"""
        return self.pfsense.get_element(self.target, root_elt=self.root_elt)

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """return obj's name"""
        return f"'{self.target}'"

    def _log_fields(self, before=None):
        """generate pseudo-CLI command fields parameters to create an obj"""
        values = ""
        if before is None:
            values += self.format_cli_field(self.obj, "enable", fvalue=self.fvalue_bool)
            values += self.format_cli_field(
                self.obj["range"], "from", fname="range_from"
            )
            values += self.format_cli_field(self.obj["range"], "to", fname="range_to")
            values += self.format_cli_field(self.obj, "failover_peerip")
            values += self.format_cli_field(self.obj, "defaultleasetime")
            values += self.format_cli_field(self.obj, "maxleasetime")
            values += self.format_cli_field(self.obj, "netmask")
            values += self.format_cli_field(self.obj, "gateway")
            values += self.format_cli_field(self.obj, "domain")
            values += self.format_cli_field(self.obj, "domainsearchlist")
            values += self.format_cli_field(self.obj, "ddnsdomain")
            values += self.format_cli_field(self.obj, "ddnsdomainprimary")
            values += self.format_cli_field(self.obj, "ddnsdomainkeyname")
            values += self.format_cli_field(self.obj, "ddnsdomainkeyalgorithm")
            values += self.format_cli_field(self.obj, "ddnsdomainkey")
            values += self.format_cli_field(self.obj, "mac_allow")
            values += self.format_cli_field(self.obj, "mac_deny")
            values += self.format_cli_field(self.obj, "ddnsclientupdates")
            values += self.format_cli_field(self.obj, "tftp")
            values += self.format_cli_field(self.obj, "ldap")
            values += self.format_cli_field(self.obj, "nextserver")
            values += self.format_cli_field(self.obj, "filename")
            values += self.format_cli_field(self.obj, "filename32")
            values += self.format_cli_field(self.obj, "filename64")
            values += self.format_cli_field(self.obj, "rootpath")
            values += self.format_cli_field(self.obj, "numberoptions")
            values += self.format_cli_field(self.obj, "denyunknown")
        else:
            values += self.format_updated_cli_field(
                self.obj, before, "enable", fvalue=self.fvalue_bool
            )
            values += self.format_updated_cli_field(
                self.obj["range"], before["range"], "from", fname="range_from"
            )
            values += self.format_updated_cli_field(
                self.obj["range"], before["range"], "to", fname="range_to"
            )
            values += self.format_updated_cli_field(self.obj, before, "failover_peerip")
            values += self.format_updated_cli_field(
                self.obj, before, "defaultleasetime"
            )
            values += self.format_updated_cli_field(self.obj, before, "maxleasetime")
            values += self.format_updated_cli_field(self.obj, before, "netmask")
            values += self.format_updated_cli_field(self.obj, before, "gateway")
            values += self.format_updated_cli_field(self.obj, before, "domain")
            values += self.format_updated_cli_field(
                self.obj, before, "domainsearchlist"
            )
            values += self.format_updated_cli_field(self.obj, before, "ddnsdomain")
            values += self.format_updated_cli_field(
                self.obj, before, "ddnsdomainprimary"
            )
            values += self.format_updated_cli_field(
                self.obj, before, "ddnsdomainkeyname"
            )
            values += self.format_updated_cli_field(
                self.obj, before, "ddnsdomainkeyalgorithm"
            )
            values += self.format_updated_cli_field(self.obj, before, "ddnsdomainkey")
            values += self.format_updated_cli_field(self.obj, before, "mac_allow")
            values += self.format_updated_cli_field(self.obj, before, "mac_deny")
            values += self.format_updated_cli_field(
                self.obj, before, "ddnsclientupdates"
            )
            values += self.format_updated_cli_field(self.obj, before, "tftp")
            values += self.format_updated_cli_field(self.obj, before, "ldap")
            values += self.format_updated_cli_field(self.obj, before, "nextserver")
            values += self.format_updated_cli_field(self.obj, before, "filename")
            values += self.format_updated_cli_field(self.obj, before, "filename32")
            values += self.format_updated_cli_field(self.obj, before, "filename64")
            values += self.format_updated_cli_field(self.obj, before, "rootpath")
            values += self.format_updated_cli_field(self.obj, before, "numberoptions")
            values += self.format_updated_cli_field(self.obj, before, "denyunknown")
        return values

    ##############################
    # run
    #
    def _update(self):
        """make the target pfsense reload"""
        return self.pfsense.phpshell(
            """
            require_once("util.inc");
            require_once("services.inc");
            services_dhcpd_configure();
            """
        )

    def _pre_remove_target_elt(self):
        self.diff["after"] = {}
        if self.target_elt is not None:
            self.diff["before"] = self.pfsense.element_to_dict(self.target_elt)
        else:
            self.diff["before"] = {}
