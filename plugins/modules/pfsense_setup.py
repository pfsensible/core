#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {"metadata_version": "1.1",
                    "status": ["preview"],
                    "supported_by": "community"}

DOCUMENTATION = """
---
module: pfsense_setup
version_added: 0.1.0
author: Frederic Bor (@f-bor)
short_description: Manage pfSense general setup
description:
  - Manage pfSense general setup
notes:
options:
  hostname:
    description: Hostname of the firewall host, without domain part
    required: false
    type: str
  domain:
    description: Domain name of the firewall host
    required: false
    type: str
  dns_addresses:
    description: Space-separated DNS IP addresses. Omit to preserve the existing addresses.
    required: false
    type: str
  dns_hostnames:
    description:
      - Space-separated DNS hostnames in DNS server order. Use C(none) for a slot without a hostname.
      - Omit to preserve the existing hostname entries, even when changing the server addresses.
    required: false
    type: str
  dns_gateways:
    description:
      - Space-separated DNS gateways in DNS server order. Use C(none) for a slot without a gateway.
      - Omit to preserve the existing gateway entries, even when changing the server addresses.
    required: false
    type: str
  dnsallowoverride:
    description: Allow DNS server list to be overridden by DHCP/PPP on WAN
    required: false
    type: bool
  dnslocalhost:
    required: false
    description: >
        Do not use the DNS Forwarder/DNS Resolver as a DNS server for the firewall.
        "" Use local DNS (127.0.0.1), fall back to remote DNS servers (Default)
        "local" Use local DNS (127.0.0), ignore remote DNS servers
        "remote" Use remote DNS server, ignore local DNS
        true will be mapped to "remote"
        false will be mapped to ""
    type: str
    choices: ["", "local", "remote", "true", "false"]
  timezone:
    description: Select a geographic region name (Continent/Location) to determine the timezone for the firewall.
    required: false
    type: str
  timeservers:
    description: Time servers, separated by space
    required: false
    type: str
  language:
    description: Language for the webConfigurator.
    required: false
    type: str
    choices: ['bs', 'de_DE', 'en_US', 'es_AR', 'es_ES', 'fr_FR', 'it_IT', 'ko_FR', 'nb_NO', 'nl_NL', 'pl_PL', 'pt_BR', 'pt_PT', 'ru_RU', 'zh_CN', 'zh_Hans_CN',
      'zh_Hans_HK', 'zh_Hant_TW']
  webguicert:
    description: SSL/TLS certificate for the web GUI.
    required: false
    type: str
    version_added: 0.7.2
  webguicss:
    description: >
        Choose an alternative CSS file (if installed) to change the appearance of the webConfigurator. Custom themes are also supported.
        If you want to use a custom pfsense CSS theme you need to upload it to the appliance first.
        Standard choices are 'pfsense', 'pfsense-dark','pfsense-dark-BETA','pfsense-BETA', and 'Compact-RED'.
    required: false
    type: str
  webguifixedmenu:
    description: When enabled, menu remains visible at top of page
    required: false
    type: bool
  webguihostnamemenu:
    description: Replaces the Help menu title in the Navbar with the system hostname or FQDN.
    required: false
    choices: ['nohost', 'hostonly', 'fqdn']
    type: str
  session_timeout:
    description: >
        Time in minutes to expire idle management sessions. The default is 4 hours (240 minutes).
        Use 0 to never expire sessions. NOTE: This is a security risk!
    required: false
    type: int
  authmode:
    description: Authentication Server ('Local Database' means local (Default)), use name of configured ldap or radius server
    required: false
    type: str
  shellauth:
    description: Use Authentication Server for Shell Authentication. Default is false.
    type: bool
  dashboardcolumns:
    description: Dashboard columns
    required: false
    type: int
  interfacessort:
    description: If selected, lists of interfaces will be sorted by description, otherwise they are listed wan,lan,optn...
    required: false
    type: bool
  dashboardavailablewidgetspanel:
    description: Show the Available Widgets panel on the Dashboard.
    required: false
    type: bool
  systemlogsfilterpanel:
    description: Show the Log Filter panel in System Logs.
    required: false
    type: bool
  systemlogsmanagelogpanel:
    description: Show the Manage Log panel in System Logs.
    required: false
    type: bool
  statusmonitoringsettingspanel:
    description: Show the Settings panel in Status Monitoring.
    required: false
    type: bool
  requirestatefilter:
    description: This option requires a filter to be entered before the states are displayed.
    required: false
    type: bool
  webguileftcolumnhyper:
    description: If selected, clicking a label in the left column will select/toggle the first item of the group.
    required: false
    type: bool
  disablealiaspopupdetail:
    description: If selected, the details in alias popups will not be shown, just the alias description (e.g. in Firewall Rules).
    required: false
    type: bool
  roworderdragging:
    description: Disables dragging rows to allow selecting and copying row contents and avoid accidental changes.
    required: false
    type: bool
  logincss:
    description:
      - Login page color as six hexadecimal digits with an optional trailing semicolon.
      - The forms C(1e3f75) and C(1e3f75;) both select Dark Blue.
    required: false
    type: str
  loginshowhost:
    description: Show hostname on login banner
    required: false
    type: bool
  nodnsrebindcheck:
    description: >
        Disable DNS Rebinding Checks. When this is not set, the system is protected against DNS Rebinding attacks. This blocks private IP responses from the
        configured DNS servers. Disable this protection if it interferes with webConfigurator access or name resolution in the environment.
    required: false
    type: bool
    version_added: 0.8.0
  nohttpreferercheck:
    description: >
      Disable HTTP_REFERER enforcement check. When this is not set, access to the webConfigurator is protected against HTTP_REFERER redirection attempts.
      Disable this protection if it interferes with webConfigurator access in certain corner cases such as using external scripts to interact with this system.
      More information on HTTP_REFERER is available from Wikipedia.
    required: false
    type: bool
    version_added: 0.8.0
  althostnames:
    description: >
      Alternate Hostnames for DNS Rebinding and HTTP_REFERER Checks: other host names or IP addresses by which the webConfigurator is reached. They are
      accepted by the DNS Rebinding and HTTP_REFERER checks. The list replaces the stored names, and an empty list removes them.
    required: false
    type: list
    elements: str
    version_added: 0.8.0
  sshguard_whitelist:
    description: Addresses (in CIDR notation) listed will bypass login protection.
    required: false
    type: list
    elements: str
    version_added: 0.7.2
  consolebell:
    description: >
      Console Bell (System > Advanced > Notifications). When set, emergency console messages, such as from a GUI login, trigger a bell in connected consoles
      including serial terminals. pfSense rings the bell when this setting has never been saved.
    required: false
    type: bool
    version_added: 0.8.0
  powerd_enable:
    description: >
      PowerD (System > Advanced > Miscellaneous). The powerd utility monitors the system state and sets various power control options accordingly, using
      the modes set by O(powerd_ac_mode), O(powerd_battery_mode) and O(powerd_normal_mode).
    required: false
    type: bool
    version_added: 0.8.0
  powerd_ac_mode:
    description: >
      PowerD mode on AC power. V(hadp) is Hiadaptive, V(adp) Adaptive, V(min) Minimum and V(max) Maximum.
      pfSense uses V(hadp) when this setting has never been saved.
    required: false
    type: str
    choices: ['hadp', 'adp', 'min', 'max']
    version_added: 0.8.0
  powerd_battery_mode:
    description: PowerD mode on battery power. The values are those of O(powerd_ac_mode).
    required: false
    type: str
    choices: ['hadp', 'adp', 'min', 'max']
    version_added: 0.8.0
  powerd_normal_mode:
    description: PowerD mode when the power source is unknown. The values are those of O(powerd_ac_mode).
    required: false
    type: str
    choices: ['hadp', 'adp', 'min', 'max']
    version_added: 0.8.0
  gw_down_kill_states:
    description: >
      State Killing on Gateway Failure (System > Advanced > Miscellaneous): what to do with the states when a gateway is down during a filter reload.
      V(none) does not kill states, V(down) kills the states of the gateways which are down, and V(all) flushes all states. Killing the states of a down
      gateway only affects the states created by policy routing rules and reply-to, and a gateway can override V(none) and V(down).
      pfSense does not kill states when this setting has never been saved.
    required: false
    type: str
    choices: ['none', 'down', 'all']
    version_added: 0.8.0
  statepolicy:
    description: >
      Firewall State Policy (System > Advanced > Firewall & NAT). V(if-bound) binds the states to their interface, V(floating) does not.
      pfSense uses V(if-bound) when this setting has never been saved. A firewall rule can override it with its own state policy.
    required: false
    type: str
    choices: ['if-bound', 'floating']
    version_added: 0.8.0
  crypto_hardware:
    description: >
      A cryptographic accelerator module will use hardware support to speed up some cryptographic functions on systems which have the chip. Loading the BSD
      Crypto Device module will allow access to acceleration devices using drivers built into the kernel, such as Hifn or ubsec chipsets. If the firewall does
      not contain a crypto chip, this option will have no effect. To unload the selected module, set this option to "" and then reboot.
    required: false
    type: str
    choices: ['', 'aesni', 'aesni_cryptodev', 'qat']
    version_added: 0.7.2
  thermal_hardware:
    description: >
      With a supported CPU, selecting a thermal sensor will load the appropriate driver to read its temperature. Setting this to "None" will attempt to read
      the temperature from an ACPI-compliant motherboard sensor instead, if one is present. If there is not a supported thermal sensor chip in the system, this
      option will have no effect. To unload the selected module, set this option to "" and then reboot.
    required: false
    type: str
    choices: ['', 'coretemp', 'amdtemp']
    version_added: 0.7.2
  ipv6allow:
    description: >
      Allow IPv6 (System > Advanced > Networking). When this is not set, all IPv6 traffic is blocked by the firewall.
    required: false
    type: bool
    version_added: 0.8.0
  maximumstates:
    description: >
      Firewall Maximum States (System > Advanced > Firewall & NAT): the maximum number of connections to hold in the firewall state table. V(0) removes the
      setting, and pfSense then uses its default, which depends on the memory of the system.
    required: false
    type: int
    version_added: 0.8.0
"""

EXAMPLES = """
- name: setup hostname and domain
  pfsense_setup:
    hostname: acme
    domain: corp.com

- name: setup theme
  pfsense_setup:
    webguicss: pfSense-dark

- name: timezone and language
  pfsense_setup:
    timezone: Europe/Paris
    language: fr
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["update setup general set hostname='acme', domain='corp.com'"]
"""

import re
from os import listdir
from os.path import isfile, join
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.arg_route import p2o_cert
from ansible_collections.pfsensible.core.plugins.module_utils.arg_validate import validate_cert
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase


SETUP_ARGUMENT_SPEC = dict(
    hostname=dict(required=False, type="str"),
    domain=dict(required=False, type="str"),
    dns_addresses=dict(required=False, type="str"),
    dns_hostnames=dict(required=False, type="str"),
    dns_gateways=dict(required=False, type="str"),
    dnsallowoverride=dict(required=False, type="bool"),
    dnslocalhost=dict(required=False, type="str", choices=[
        "",
        "local",
        "remote",
        "true",
        "false",
    ]),
    timezone=dict(required=False, type="str"),
    timeservers=dict(required=False, type="str"),
    language=dict(
        required=False,
        type="str",
        choices=["bs", "de_DE", "en_US", "es_AR", "es_ES", "fr_FR", "it_IT", "ko_FR", "nb_NO", "nl_NL", "pl_PL", "pt_BR", "pt_PT", "ru_RU", "zh_CN",
                 "zh_Hans_CN", "zh_Hans_HK", "zh_Hant_TW"],
    ),
    session_timeout=dict(required=False, type="int"),
    authmode=dict(required=False, type="str"),
    shellauth=dict(required=False, type="bool"),
    webguicert=dict(required=False, type="str"),
    webguicss=dict(required=False, type="str"),
    webguifixedmenu=dict(required=False, type="bool"),
    webguihostnamemenu=dict(required=False, type="str", choices=["nohost", "hostonly", "fqdn"]),
    dashboardcolumns=dict(required=False, type="int"),
    interfacessort=dict(required=False, type="bool"),
    dashboardavailablewidgetspanel=dict(required=False, type="bool"),
    systemlogsfilterpanel=dict(required=False, type="bool"),
    systemlogsmanagelogpanel=dict(required=False, type="bool"),
    statusmonitoringsettingspanel=dict(required=False, type="bool"),
    requirestatefilter=dict(required=False, type="bool"),
    webguileftcolumnhyper=dict(required=False, type="bool"),
    disablealiaspopupdetail=dict(required=False, type="bool"),
    roworderdragging=dict(required=False, type="bool"),
    logincss=dict(required=False, type="str"),
    loginshowhost=dict(required=False, type="bool"),
    nodnsrebindcheck=dict(required=False, type="bool"),
    nohttpreferercheck=dict(required=False, type="bool"),
    sshguard_whitelist=dict(required=False, type="list", elements="str"),
    consolebell=dict(required=False, type="bool"),
    powerd_enable=dict(required=False, type="bool"),
    powerd_ac_mode=dict(required=False, type="str", choices=["hadp", "adp", "min", "max"]),
    powerd_battery_mode=dict(required=False, type="str", choices=["hadp", "adp", "min", "max"]),
    powerd_normal_mode=dict(required=False, type="str", choices=["hadp", "adp", "min", "max"]),
    gw_down_kill_states=dict(required=False, type="str", choices=["none", "down", "all"]),
    statepolicy=dict(required=False, type="str", choices=["if-bound", "floating"]),
    crypto_hardware=dict(required=False, type="str", choices=["", "aesni", "aesni_cryptodev", "qat"]),
    thermal_hardware=dict(required=False, type="str", choices=["", "coretemp", "amdtemp"]),
    althostnames=dict(required=False, type="list", elements="str"),
    ipv6allow=dict(required=False, type="bool"),
    maximumstates=dict(required=False, type="int"),
)


def p2o_dnslocalhost(self, name, params, obj):
    if params[name] is not None:
        if str(params.get(name)).lower() in ["", "false"]:
            obj[name] = ""
        elif str(params.get(name)).lower() in ["remote", "true"]:
            obj[name] = "remote"
        elif params.get(name).lower() == "local":
            obj[name] = "local"


def p2o_network_list_to_space_separated(self, name, params, obj):
    if params[name] is not None:
        for net in params[name]:
            if not (self.pfsense.is_ipv4_network(net, strict=False) or self.pfsense.is_ipv6_network(net, strict=False)):
                self.module.fail_json(msg=f"Address {net} is not a valid network")
        obj[name] = " ".join(params[name])


def p2o_space_separated(self, name, params, obj):
    if params[name] is not None:
        obj[name] = " ".join(params[name])


def p2o_maximumstates(self, name, params, obj):
    # 0 means pfSense's default: _params_to_obj() removes the setting
    if params[name] is not None:
        obj[name] = str(params[name])


def p2o_webguicss(self, name, params, obj):
    if params[name] is not None:
        # Add .css suffix if not present
        if params[name][-4:] != ".css":
            obj[name] = params[name] + ".css"
        else:
            obj[name] = params[name]


def p2o_logincss(self, name, params, obj):
    color = params[name].lower().rstrip(";")
    current = (obj.get("webgui") or {}).get(name)
    if isinstance(current, str) and current.lower() in (color, color + ";"):
        obj[name] = current
    else:
        # The pfSense color picker uses a trailing semicolon for Dark Blue.
        obj[name] = "1e3f75;" if color == "1e3f75" else color


def validate_webguicss(self, webguicss):
    """ check css style """
    path = "/usr/local/www/css/"
    themes = [f for f in listdir(path) if isfile(join(path, f)) and f.endswith(".css") and f.find("login") == -1 and f.find("logo") == -1]
    themes = map(lambda x: x.replace(".css", ""), themes)
    if webguicss.rstrip(".css") not in themes:
        raise ValueError("The submitted theme '%s' could not be found. Pick a different theme." % webguicss)


# TODO - validate crypto_hardware against $crypto_modules = getSystemAdvancedMiscCryptoModules();
SETUP_ARG_ROUTE = dict(
    dnslocalhost=dict(parse=p2o_dnslocalhost),
    logincss=dict(parse=p2o_logincss),
    sshguard_whitelist=dict(parse=p2o_network_list_to_space_separated),
    althostnames=dict(parse=p2o_space_separated),
    maximumstates=dict(parse=p2o_maximumstates),
    webguicert=dict(parse=p2o_cert, validate=validate_cert),
    webguicss=dict(parse=p2o_webguicss, validate=validate_webguicss),
)

# Booleans that map to different values
SETUP_BOOL_VALUES = dict(
    consolebell=("disabled", "enabled"),
    webguifixedmenu=(None, "fixed"),
)

POWERD_PARAMS = ("powerd_enable", "powerd_ac_mode", "powerd_battery_mode", "powerd_normal_mode")

SETUP_MAP_PARAM = [
    ("althostnames", "webgui/althostnames"),
    ("authmode", "webgui/authmode"),
    ("dashboardavailablewidgetspanel", "webgui/dashboardavailablewidgetspanel"),
    ("dashboardcolumns", "webgui/dashboardcolumns"),
    ("disablealiaspopupdetail", "webgui/disablealiaspopupdetail"),
    ("interfacessort", "webgui/interfacessort"),
    ("logincss", "webgui/logincss"),
    ("loginshowhost", "webgui/loginshowhost"),
    ("nodnsrebindcheck", "webgui/nodnsrebindcheck"),
    ("nohttpreferercheck", "webgui/nohttpreferercheck"),
    ("requirestatefilter", "webgui/requirestatefilter"),
    ("roworderdragging", "webgui/roworderdragging"),
    ("session_timeout", "webgui/session_timeout"),
    ("shellauth", "webgui/shellauth"),
    ("statusmonitoringsettingspanel", "webgui/statusmonitoringsettingspanel"),
    ("systemlogsfilterpanel", "webgui/systemlogsfilterpanel"),
    ("systemlogsmanagelogpanel", "webgui/systemlogsmanagelogpanel"),
    ("webguicert", "webgui/ssl-certref"),
    ("webguicss", "webgui/webguicss"),
    ("webguifixedmenu", "webgui/webguifixedmenu"),
    ("webguihostnamemenu", "webgui/webguihostnamemenu"),
    ("webguileftcolumnhyper", "webgui/webguileftcolumnhyper"),
]


class PFSenseSetupModule(PFSenseModuleConfigBase):
    """ module managing pfsense routes """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return SETUP_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseSetupModule, self).__init__(module, pfsense, name="pfsense_setup", root="pfsense", node="system", arg_route=SETUP_ARG_ROUTE,
                                                 bool_style="absent/present", bool_values=SETUP_BOOL_VALUES, map_param=SETUP_MAP_PARAM)
        self.route_cmds = list()
        self.params_to_delete = list()

    ##############################
    # params processing
    #
    @staticmethod
    def _dns_addresses(obj):
        addresses = obj.get("dnsserver") or []
        return [addresses] if isinstance(addresses, str) else addresses

    @staticmethod
    def _dns_slots(obj, suffix):
        slots = {}
        for key, value in obj.items():
            match = re.fullmatch(r"dns([1-9][0-9]*)" + suffix, key)
            if match:
                slots[int(match.group(1))] = value
        return slots

    def _dns_params_to_obj(self, params, obj):
        """Apply only the DNS options supplied by the task."""
        if params.get("dns_addresses") is not None:
            obj["dnsserver"] = obj.pop("dns_addresses").split()

        addresses = self._dns_addresses(obj)
        for param, suffix in (("dns_hostnames", "host"), ("dns_gateways", "gw")):
            if params.get(param) is None:
                continue

            values = obj.pop(param).split()
            previous = self._dns_slots(obj, suffix)
            for index, address in enumerate(addresses, 1):
                if index <= len(values):
                    value = values[index - 1]
                elif suffix == "host":
                    previous.pop(index, None)
                    continue
                else:
                    value = "none"
                if suffix == "host" and value == "none":
                    continue

                key = "dns{0}{1}".format(index, suffix)
                obj[key] = value
                if suffix == "gw" and value != previous.get(index):
                    if self.pfsense.is_ipv4_address(address):
                        self.route_cmds.append("/sbin/route delete {0}".format(address))
                    elif self.pfsense.is_ipv6_address(address):
                        self.route_cmds.append("/sbin/route delete -inet6 {0}".format(address))
                previous.pop(index, None)

            for index in previous:
                key = "dns{0}{1}".format(index, suffix)
                del obj[key]
                self.params_to_delete.append(key)

    def _params_to_obj(self):
        """ return a dict from module params """
        obj = super(PFSenseSetupModule, self)._params_to_obj()
        webgui = obj.get("webgui") or {}
        # Mapped WebGUI flags are stored by presence. Drop disabled flags from the copied configuration.
        for param, path in SETUP_MAP_PARAM:
            if self.params.get(param) is False:
                webgui.pop(path.rsplit("/", 1)[-1], None)
        # As the web GUI does, no value removes the setting
        if self.params.get("althostnames") == []:
            webgui.pop("althostnames", None)
        if self.params.get("maximumstates") == 0:
            obj.pop("maximumstates", None)
            self.params_to_delete.append("maximumstates")
        self._dns_params_to_obj(self.params, obj)
        return obj

    def _validate_hostname(self, hostname, name, strict=False):
        """ check hostname, if strict is true, check if domain is omitted """
        host = hostname.lower()
        groups = re.match(r"^(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$", host)
        if groups is None:
            self.module.fail_json(msg="The {0} can only contain the characters A-Z, 0-9 and '-'. It may not start or end with '-'".format(name))

        if strict:
            groups = re.match(r"^(?:[a-z0-9_]|[a-z0-9_][a-z0-9_\-]*[a-z0-9_])$", host)
            if groups is None:
                self.module.fail_json(msg="A valid {0} is specified, but the domain name part should be omitted".format(name))

    def _validate_params(self):
        """ do some extra checks on input parameters """
        super(PFSenseSetupModule, self)._validate_params()
        params = self.params

        if params.get("dashboardcolumns") is not None and (params["dashboardcolumns"] < 1 or params["dashboardcolumns"] > 6):
            self.module.fail_json(msg="The submitted Dashboard Columns value is invalid.")

        if params.get("althostnames") is not None:
            for althostname in params["althostnames"]:
                if not (self.pfsense.is_ipv4_address(althostname) or self.pfsense.is_ipv6_address(althostname)):
                    self._validate_hostname(althostname, "alternate hostname {0}".format(althostname))

        if params.get("maximumstates") is not None and params["maximumstates"] < 0:
            self.module.fail_json(msg="The Firewall Maximum States value must be 0 or more.")

        if params.get("domain") is not None:
            domain = params["domain"].lower()
            groups = re.match(r"^(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$", domain)
            if groups is None:
                self.module.fail_json(msg="The domain may only contain the characters a-z, 0-9, '-' and '.'")

        if params.get("hostname") is not None:
            self._validate_hostname(params["hostname"], "hostname", True)

        if params.get("logincss") is not None and not re.fullmatch(r"[0-9a-fA-F]{6};?", params["logincss"]):
            self.module.fail_json(msg="logincss must contain six hexadecimal digits with an optional trailing semicolon.")

        if params.get("timezone") is not None:
            self._validate_timezone(params["timezone"])

        if params.get("timeservers") is not None:
            for timeserver in params["timeservers"].split(" "):
                self._validate_hostname(timeserver, "timeserver")

        if params.get("authmode") is not None:
            value = params.get("authmode")
            if value != "Local Database":
                authserver_elt = self.pfsense.find_elt("authserver", value, search_field="name", root_elt=self.root_elt.find(self.node))
                if authserver_elt is None:
                    self.module.fail_json(msg="Given authserver '{0}' could not be found.".format(value))

                if params.get("shellauth") is not None and params.get("shellauth") is True:
                    if authserver_elt.find("type").text == "ldap":
                        # check if ldap_pam_groupdn is set
                        if authserver_elt.find("ldap_pam_groupdn") is None or \
                           authserver_elt.find("ldap_pam_groupdn").text is None or \
                           authserver_elt.find("ldap_pam_groupdn").text == "":
                            self.module.fail_json(msg="ldap_pam_groupdn not set for authserver '{0}'.".format(value))

        # DNS
        dns_addresses = []
        if params.get("dns_addresses") is not None:
            dns_addresses = params["dns_addresses"].split()
            for address in dns_addresses:
                if dns_addresses.count(address) > 1:
                    self.module.fail_json(msg="Each configured DNS server must have a unique IP address. Remove the duplicated IP.")

                if not (self.pfsense.is_ipv4_address(address) or self.pfsense.is_ipv6_address(address)):
                    self.module.fail_json(msg="A valid IP address must be specified for DNS server {0}.".format(address))

        if params.get("dns_hostnames") is not None:
            for hostname in params["dns_hostnames"].split():
                if hostname != "none":
                    self._validate_hostname(hostname, "DNS hostname")

        if params.get("dns_gateways") is not None:
            if params.get("dns_addresses") is None:
                dns_addresses = [elt.text or "" for elt in self.root_elt.findall("system/dnsserver")]
            for idx, address in enumerate(params["dns_gateways"].split()):
                if idx >= len(dns_addresses) or address == "none":
                    continue

                if self.pfsense.find_gateway_elt(address, protocol="inet") is not None:
                    if self.pfsense.is_ipv6_address(dns_addresses[idx]):
                        self.module.fail_json(msg='The IPv4 gateway "{0}" can not be specified for IPv6 DNS server "{1}".'.format(address, dns_addresses[idx]))
                elif self.pfsense.find_gateway_elt(address, protocol="inet6") is not None:
                    if self.pfsense.is_ipv4_address(dns_addresses[idx]):
                        self.module.fail_json(msg='The IPv6 gateway "{0}" can not be specified for IPv4 DNS server "{1}".'.format(address, dns_addresses[idx]))
                else:
                    self.module.fail_json(msg='The gateway "{0}" does not exist.'.format(address))

                if self.pfsense.is_within_local_networks(dns_addresses[idx]):
                    self.module.fail_json(
                        msg="A gateway can not be assigned to DNS '{0}' server which is on a directly connected network.".format(dns_addresses[idx])
                    )

    def _validate_timezone(self, timezone):
        """ check timezone """
        path = "/usr/share/zoneinfo/"
        if not isfile(path + timezone) or timezone[:1] < "A" or timezone[:1] > "Z":
            self.module.fail_json(msg="The submitted timezone is invalid")

    ##############################
    # XML processing
    #
    def _get_params_to_remove(self):
        """ returns the list of params to remove if they are not set """
        to_remove = super(PFSenseSetupModule, self)._get_params_to_remove()
        to_remove.extend(self.params_to_delete)
        return to_remove

    ##############################
    # run
    #
    @staticmethod
    def _diff_fields(values):
        """ the fields of the system section the module manages """
        mapped = dict(SETUP_MAP_PARAM)
        webgui_fields = [path.split("/", 1)[1] for path in mapped.values()]
        fields = dict()
        for key, value in values.items():
            if key == "webgui" and isinstance(value, dict):
                fields[key] = dict((field, value[field]) for field in value if field in webgui_fields)
            elif (key in SETUP_ARGUMENT_SPEC and key not in mapped) or key == "dnsserver" or re.fullmatch(r"dns[0-9]+(host|gw)", key):
                fields[key] = value
        return fields

    def _run_post(self):
        # The diff of the whole system section would show the users with their password hashes, the authentication servers
        # with their secrets, the AutoConfigBackup password...: keep the fields the module manages
        for side in ("before", "after"):
            self.diff[side] = self._diff_fields(self.diff.get(side) or {})

    def _update(self):
        """ make the target pfsense reload """
        for cmd in self.route_cmds:
            self.module.run_command(cmd)

        cmd = """
require_once("auth.inc");
require_once("filter.inc");
require_once("pfsense-utils.inc");
require_once("system_advanced_admin.inc");
$retval = 0;
$retval |= system_hostname_configure();
$retval |= system_hosts_generate();
$retval |= system_resolvconf_generate();
if (config_path_enabled('dnsmasq')) {
        $retval |= services_dnsmasq_configure();
} elseif (config_path_enabled('unbound')) {
        $retval |= services_unbound_configure();
}
$retval |= system_timezone_configure();
$retval |= system_ntp_configure();
load_crypto();
load_thermal_hardware();"""

        if self.params.get("dnsallowoverride") is not None:
            if (self.params["dnsallowoverride"] and "dnsallowoverride" not in self.diff["before"] or
                    not self.params["dnsallowoverride"] and "dnsallowoverride" in self.diff["before"]):
                cmd += '$retval |= send_event("service reload dns");\n'

        if self.params.get("shellauth") is not None:
            cmd += "$retval |= set_pam_auth();"

        # What System > Advanced > Networking and Firewall & NAT do when these change
        if self.obj.get("ipv6allow") != self.diff["before"].get("ipv6allow"):
            cmd += "prefer_ipv4_or_ipv6();\n"
        if self.obj.get("maximumstates") != self.diff["before"].get("maximumstates"):
            cmd += "setup_loader_settings();\n"

        cmd += "$retval |= filter_configure();\n"

        restart_sshguard = False
        for param in ["sshguard_whitelist"]:
            if self.obj.get(param) != self.diff["before"].get(param):
                restart_sshguard = True
        if restart_sshguard:
            cmd += "system_sshguard_stop();$retval |= system_syslogd_start(true);\n"

        # What System > Advanced > Notifications and Miscellaneous do when these change. The state policy and the
        # gateway state killing need only the filter reload above.
        if self.obj.get("consolebell") != self.diff["before"].get("consolebell"):
            cmd += "set_single_sysctl('kern.vt.enable_bell', '{0}');\n".format("0" if self.obj.get("consolebell") == "disabled" else "1")
        if any(self.obj.get(param) != self.diff["before"].get(param) for param in POWERD_PARAMS):
            cmd += "activate_powerd();\n"

        webgui = self.obj.get("webgui") or {}
        before_webgui = self.diff["before"].get("webgui") or {}
        if webgui.get("ssl-certref") != before_webgui.get("ssl-certref"):
            cmd += "restart_GUI();\n"

        self.result["cmd"] = cmd
        return self.pfsense.phpshell(cmd)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "general"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        bwebgui = self.diff["before"].get("webgui") or {}
        webgui = self.obj.get("webgui") or {}

        obj_before = self._prepare_dns_log(self.diff["before"])
        obj_after = self._prepare_dns_log(self.obj)

        values = ""
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "hostname", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "domain", add_comma=(values), log_none=False)

        values += self.format_updated_cli_field(obj_after, obj_before, "dns_addresses", add_comma=(values), log_none=True)
        values += self.format_updated_cli_field(obj_after, obj_before, "dns_hostnames", add_comma=(values), log_none=True)
        values += self.format_updated_cli_field(obj_after, obj_before, "dns_gateways", add_comma=(values), log_none=True)

        values += self.format_updated_cli_field(self.obj, self.diff["before"], "timezone", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "timeservers", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "language", add_comma=(values), log_none=False)

        values += self.format_updated_cli_field(self.obj, self.diff["before"], "dnsallowoverride", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "dnslocalhost", add_comma=(values), log_none=False)

        values += self.format_updated_cli_field(self.obj, self.diff["before"], "consolebell", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "powerd_enable", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "powerd_ac_mode", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "powerd_battery_mode", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "powerd_normal_mode", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "gw_down_kill_states", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "statepolicy", add_comma=(values), log_none=False)

        values += self.format_updated_cli_field(obj_after, obj_before, "webguicert", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(obj_after, obj_before, "webguicss", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "webguifixedmenu", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "webguihostnamemenu", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "dashboardcolumns", add_comma=(values), log_none=False)

        values += self.format_updated_cli_field(webgui, bwebgui, "interfacessort", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "dashboardavailablewidgetspanel", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "systemlogsfilterpanel", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "systemlogsmanagelogpanel", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "statusmonitoringsettingspanel", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "requirestatefilter", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "webguileftcolumnhyper", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "disablealiaspopupdetail", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "roworderdragging", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "logincss", add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "loginshowhost", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "nodnsrebindcheck", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "nohttpreferercheck", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, "althostnames", add_comma=(values), log_none=True)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "ipv6allow", fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.diff["before"], "maximumstates", add_comma=(values), log_none=True)

        return values

    def _prepare_dns_log(self, obj):
        """ construct dict for logging """
        ret = dict()
        webgui = obj.get("webgui") or {}

        ret["webguicss"] = webgui["webguicss"].replace(".css", "") if "webguicss" in webgui else None

        ret["dns_addresses"] = " ".join(self._dns_addresses(obj)) or None
        for param, suffix in (("dns_hostnames", "host"), ("dns_gateways", "gw")):
            slots = self._dns_slots(obj, suffix)
            last = max((index for index, value in slots.items() if value and value != "none"), default=0)
            ret[param] = " ".join(slots.get(index) or "none" for index in range(1, last + 1)) or None
        return ret


def main():
    module = AnsibleModule(
        argument_spec=SETUP_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseSetupModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
