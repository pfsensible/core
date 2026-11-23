# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Carlos Rodrigues <cmarodrigues@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ipaddress import ip_address, ip_network
import re

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

DHCP_STATIC_ARGUMENT_SPEC = dict(
    name=dict(type="str", aliases=["cid"]),
    macaddr=dict(type="str"),
    netif=dict(type="str"),
    ipaddr=dict(type="str"),
    hostname=dict(type="str"),
    descr=dict(type="str"),
    filename=dict(type="str"),
    rootpath=dict(type="str"),
    defaultleasetime=dict(type="str"),
    maxleasetime=dict(type="str"),
    gateway=dict(type="str"),
    domain=dict(type="str"),
    domainsearchlist=dict(type="str"),
    winsserver=dict(type="list", elements="str"),
    dnsserver=dict(type="list", elements="str"),
    ntpserver=dict(type="list", elements="str"),
    ddnsdomain=dict(type="str"),
    ddnsdomainprimary=dict(type="str"),
    ddnsdomainsecondary=dict(type="str"),
    ddnsdomainkeyname=dict(type="str", no_log=False),
    ddnsdomainkeyalgorithm=dict(type="str", choices=["hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512"]),
    ddnsdomainkey=dict(type="str", no_log=True),
    tftp=dict(type="str"),
    ldap=dict(type="str"),
    nextserver=dict(type="str"),
    filename32=dict(type="str"),
    filename64=dict(type="str"),
    filename32arm=dict(type="str"),
    filename64arm=dict(type="str"),
    uefihttpboot=dict(type="str"),
    numberoptions=dict(type="str"),
    arp_table_static_entry=dict(default=False, type="bool"),
    state=dict(type="str", default="present", choices=["present", "absent"]),
)

DHCP_STATIC_REQUIRED_IF = [
    ["arp_table_static_entry", True, ["ipaddr"]],
]

DHCP_STATIC_REQUIRED_ONE_OF = [
    ("name", "macaddr"),
]


class PFSenseDHCPStaticModule(PFSenseModuleBase):
    """ module managing pfsense dhcp static configuration """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DHCP_STATIC_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDHCPStaticModule, self).__init__(module, pfsense)
        self.name = "pfsense_dhcp_static"
        # Override for use with aggregate
        self.argument_spec = DHCP_STATIC_ARGUMENT_SPEC
        self.dhcpd = self.pfsense.get_element("dhcpd")
        self.root_elt = None
        self.staticmaps = None

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """

        params = self.params

        if params["macaddr"] is not None and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", params["macaddr"]) is None:
            self.module.fail_json(msg="A valid MAC address must be specified.")

        if params["netif"] is not None:
            if self.pfsense.is_interface_group(params["netif"]):
                self.module.fail_json(msg="DHCP cannot be configured for interface groups")
            else:
                netif = self.pfsense.parse_interface(params["netif"])
        else:
            netif = None

        # find staticmaps and determine interface
        self._find_staticmaps(netif)

        if params["ipaddr"] is not None:
            addr = ip_address(u"{0}".format(params["ipaddr"]))
            if addr not in self.network:
                self.module.fail_json(msg="The IP address must lie in the {0} subnet.".format(self.netif))

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj
        # client identifier
        self._get_ansible_param(obj, "name", fname="cid", force=True)
        self._get_ansible_param(obj, "macaddr", fname="mac", force=True)

        if params["state"] == "present":

            # Forced options
            for option in ["ipaddr", "hostname", "descr", "filename",
                           "rootpath", "defaultleasetime", "maxleasetime",
                           "gateway", "domain", "domainsearchlist",
                           "ddnsdomain", "ddnsdomainprimary", "ddnsdomainsecondary",
                           "ddnsdomainkeyname", "ddnsdomainkeyalgorithm", "ddnsdomainkey",
                           "tftp", "ldap", "nextserver", "filename32", "filename64",
                           "filename32arm", "filename64arm", "uefihttpboot", "numberoptions"]:
                self._get_ansible_param(obj, option, force=True)
            # Non-forced options
            for option in ["winsserver", "dnsserver", "ntpserver"]:
                self._get_ansible_param(obj, option)
            # Defaulted options
            self._get_ansible_param(obj, "ddnsdomainkeyalgorithm", force_value="hmac-md5", force=True)
            self._get_ansible_param_bool(obj, "arp_table_static_entry", value="")

        return obj

    ##############################
    # XML processing
    #
    def _is_valid_netif(self, netif):
        for nic in self.pfsense.interfaces:
            if nic.tag == netif:
                if nic.find("ipaddr") is not None:
                    ipaddr = nic.find("ipaddr").text
                    if ipaddr is not None:
                        if nic.findtext("subnet"):
                            subnet = int(nic.find("subnet").text)
                            if subnet < 31:
                                self.network = ip_network(u"{0}/{1}".format(ipaddr, subnet), strict=False)
                                return True
        return False

    def _find_staticmaps(self, netif=None):
        # Reset per item, so a single instance can process many (pfsense_aggregate)
        self.root_elt = None
        for e in self.dhcpd:
            if netif is None or e.tag == netif:
                if e.find("enable") is not None:
                    if self._is_valid_netif(e.tag):
                        if self.root_elt is not None:
                            self.module.fail_json(msg="Multiple DHCP servers enabled and no netif specified")
                        self.root_elt = e
                        self.netif = e.tag
                        self.staticmaps = self.root_elt.findall("staticmap")
                        if netif is not None:
                            break

        if self.root_elt is None:
            if netif is None:
                self.module.fail_json(msg="No DHCP configuration")
            else:
                self.module.fail_json(msg="No DHCP configuration found for netif='{0}'".format(netif))

        self.result["netif"] = netif

    def _find_target(self):
        if self.params["name"] is not None and self.params["macaddr"] is not None:
            result = self.root_elt.findall("staticmap[cid='{0}'][mac='{1}']".format(self.params["name"], self.params["macaddr"]))
        elif self.params["name"] is not None:
            result = self.root_elt.findall("staticmap[cid='{0}']".format(self.params["name"]))
        else:
            result = self.root_elt.findall("staticmap[mac='{0}']".format(self.params["macaddr"]))

        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg="Found multiple static maps for cid {0}.".format(self.obj["cid"]))
        else:
            return None

    def managed_dhcp_servers(self):
        """ return the DHCP server elements whose static maps this module manages """
        if self.dhcpd is None:
            return []
        return [e for e in self.dhcpd if e.find("enable") is not None and self._is_valid_netif(e.tag)]

    def remove_staticmap(self, dhcp_elt, staticmap_elt):
        """ remove a static map element of dhcp_elt as is, without searching for it by cid or mac """
        self.root_elt = dhcp_elt
        self.staticmaps = dhcp_elt.findall("staticmap")
        self.target_elt = staticmap_elt
        self.obj = dict(cid=staticmap_elt.findtext("cid") or "", mac=staticmap_elt.findtext("mac") or "")
        self._remove()

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element("staticmap")

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        super(PFSenseDHCPStaticModule, self)._copy_and_add_target()
        # Reset static map list
        self.staticmaps = self.root_elt.findall("staticmap")

    @staticmethod
    def _get_params_to_remove():
        """ returns the list of params to remove if they are not set """
        return ["arp_table_static_entry"]

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}'".format(self.obj["cid"] or self.obj["mac"])

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ""
        if before is None:
            values += self.format_cli_field(self.params, "macaddr")
            values += self.format_cli_field(self.params, "ipaddr")
            values += self.format_cli_field(self.params, "hostname")
            values += self.format_cli_field(self.params, "descr")
            values += self.format_cli_field(self.params, "arp_table_static_entry", fvalue=self.fvalue_bool, default=False)
        else:
            values += self.format_updated_cli_field(self.obj, before, "macaddr", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "ipaddr", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "hostname", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "descr", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "arp_table_static_entry", fvalue=self.fvalue_bool, add_comma=(values))
        return values

    ##############################
    # run
    #
    @staticmethod
    def get_update_cmds():
        """ build and return php commands to reload the DHCP server """
        return """
            require_once("util.inc");
            require_once("services.inc");
            $retvaldhcp = services_dhcpd_configure();
            if ($retvaldhcp == 0) {
              clear_subsystem_dirty('dhcpd');
            }"""

    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell(self.get_update_cmds())

    def _pre_remove_target_elt(self):
        self.diff["after"] = {}
        if self.target_elt is not None:
            self.diff["before"] = self.pfsense.element_to_dict(self.target_elt)

            self.staticmaps.remove(self.target_elt)
        else:
            self.diff["before"] = {}
