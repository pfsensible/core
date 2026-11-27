#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Romain Tiennot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_ipsec_settings

short_description: Manage the IPsec advanced settings

version_added: "0.8.0"

description:
  - Manage VPN > IPsec > Advanced Settings, the log levels of strongSwan and the IPsec settings shared by all tunnels.
  - Omitted options preserve existing settings.
  - As the Save button of the page does, the firewall rules, the IPsec configuration and the system tunables are reloaded after a
    change. strongSwan is restarted when O(compression), O(pkcs11support), O(enableinterfacesuse), O(acceptunencryptedmainmode),
    O(maxexchange) or O(unityplugin) change, and reloaded otherwise.

notes:
  - On an HA pair with IPsec in the configuration sync (System > High Availability), the primary copies the whole IPsec section,
    these settings included, to the secondary. The module does not start that sync. Run it on both nodes, or start a sync
    afterwards, for example with M(pfsensible.core.pfsense_rewrite_config).

options:
  logging:
    description:
      - Log level of each strongSwan subsystem, from V(-1) to V(4) (Silent, Audit, Control, Diag, Raw, Highest).
      - When no level is stored for a subsystem, pfSense uses V(2) for O(logging.ike), O(logging.chd) and O(logging.cfg), and V(1)
        for the others. Saving the page stores the level of every subsystem.
    type: dict
    suboptions:
      dmn:
        description: Daemon.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      mgr:
        description: SA Manager.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      ike:
        description: IKE SA.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      chd:
        description: IKE Child SA.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      job:
        description: Job Processing.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      cfg:
        description: Configuration backend.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      knl:
        description: Kernel Interface.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      net:
        description: Networking.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      asn:
        description: ASN encoding.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      enc:
        description: Message encoding.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      imc:
        description: Integrity checker.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      imv:
        description: Integrity Verifier.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      pts:
        description: Platform Trust Service.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      tls:
        description: TLS handler.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      esp:
        description: IPsec traffic.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
      lib:
        description: StrongSwan Lib.
        type: int
        choices: [-1, 0, 1, 2, 3, 4]
  uniqueids:
    description:
      - What happens when a new IKE SA uses the ID of an existing one. V(replace) replaces the old one. With V(no), the old one is
        replaced only when the peer sends an INITIAL_CONTACT notify. V(never) ignores these notifies. V(keep) rejects the new one.
      - pfSense uses V(replace) when none is stored.
    type: str
    choices: [replace, 'no', never, keep]
  filtermode:
    description:
      - V(enc) filters tunnel, transport and VTI traffic with the rules of the IPsec tab (enc0).
      - V(if_ipsec) filters VTI and transport traffic on the assigned interfaces, and blocks all tunnel mode traffic.
      - pfSense uses V(enc) when none is stored.
    type: str
    choices: [enc, if_ipsec]
  ikev2_retransmit_tries:
    description: Number of IKEv2 retransmissions before giving up. V(0) removes it, and strongSwan uses 5.
    type: int
  ikev2_retransmit_timeout:
    description: Timeout of IKEv2 retransmissions, in seconds. V(0) removes it, and strongSwan uses 4.0.
    type: float
  ikev2_retransmit_base:
    description: Base of the exponential backoff of IKEv2 retransmissions. V(0) removes it, and strongSwan uses 1.8.
    type: float
  ikev2_retransmit_jitter:
    description: Maximum jitter, in percent, applied at random to the IKEv2 retransmission timeout. V(0) removes it (no jitter).
    type: int
  ikev2_retransmit_limit:
    description: Upper limit of the IKEv2 retransmission timeout, in seconds. V(0) removes it (no limit).
    type: int
  compression:
    description: Propose IPComp compression on the connections. pfSense stores this setting but does not use it at the moment.
    type: bool
  pkcs11support:
    description:
      - Allow PKCS#11 tokens for phase 1 authentication.
      - As in the web GUI, it cannot be disabled while an enabled phase 1 uses PKCS#11 authentication.
    type: bool
  enableinterfacesuse:
    description: Bind strongSwan to the interfaces of the phases 1 only (strict interface binding). It breaks IPsec on dynamic interfaces.
    type: bool
  acceptunencryptedmainmode:
    description: Accept unencrypted ID and HASH payloads in IKEv1 Main Mode, which some devices send.
    type: bool
  maxexchange:
    description:
      - Number of IKEv1 phase 2 exchanges (rekeys) that can run in parallel with one peer, from 3 to 64.
      - V(0) removes it, and strongSwan uses 3.
    type: int
  unityplugin:
    description: Enable the Unity plugin, for the Cisco extensions (Split-Include, Split-Exclude and Split-DNS).
    type: bool
  strictcrlpolicy:
    description: Require a fresh certificate revocation list to authenticate a peer with a certificate.
    type: bool
  dns_interval:
    description: Interval, in seconds, between two resolutions of remote gateways given by name. V(0) removes it, and pfSense uses 60.
    type: int
  makebeforebreak:
    description: Make IKEv2 reauthentications make-before-break instead of break-before-make. The peer must support overlapping SAs.
    type: bool
  async_crypto:
    description:
      - Dispatch the crypto(9) jobs of IPsec to several threads (sysctl C(net.inet.ipsec.async_crypto)).
      - pfSense leaves it off when none is stored. It sets the sysctl only while at least one phase 1 is enabled.
    type: bool
  port:
    description: Local UDP port of IKE. V(0) removes it, and strongSwan uses 500.
    type: int
  port_nat_t:
    description: Local UDP port of NAT-T. V(0) removes it, and strongSwan uses 4500.
    type: int
  noshuntlaninterfaces:
    description:
      - Do not exclude the traffic from the LAN subnet to the LAN address from IPsec.
      - It is the opposite of the Auto-exclude LAN address check box of the web GUI.
    type: bool
  ipsecbypass:
    description:
      - Exclude the traffic of O(bypassrules) from IPsec. As in the web GUI, it needs at least one rule.
      - Disabling it also removes the rules, as the web GUI does.
    type: bool
  bypassrules:
    description:
      - Traffic to exclude from IPsec. The rules given replace the stored ones.
      - Requires O(ipsecbypass).
    type: list
    elements: dict
    suboptions:
      source:
        description: Source network, as address/bits. IPv4 or IPv6.
        type: str
        required: true
      destination:
        description: Destination network, as address/bits, of the same address family as O(bypassrules[].source).
        type: str
        required: true

author: Romain Tiennot (@RomainTie)
"""

EXAMPLES = r"""
- name: Use asynchronous cryptography and the default log levels of pfSense
  pfsensible.core.pfsense_ipsec_settings:
    async_crypto: true
    logging:
      dmn: 1
      mgr: 1
      ike: 2
      chd: 2
      job: 1
      cfg: 2
      knl: 1
      net: 1
      asn: 1
      enc: 1
      imc: 1
      imv: 1
      pts: 1
      tls: 1
      esp: 1
      lib: 1

- name: Log the IKE negotiations in full
  pfsensible.core.pfsense_ipsec_settings:
    logging:
      ike: 4

- name: Exclude the traffic between two local networks from IPsec
  pfsensible.core.pfsense_ipsec_settings:
    ipsecbypass: true
    bypassrules:
      - source: 192.168.1.0/24
        destination: 192.168.2.0/24
"""

RETURN = r"""
commands:
    description: Pseudo-CLI commands describing configuration changes.
    returned: always
    type: list
    elements: str
    sample: ["update ipsec_settings ipsec set logging.ike='2', async_crypto=True"]
"""

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

LOG_LEVELS = [-1, 0, 1, 2, 3, 4]
# $ipsec_log_cats of /etc/inc/ipsec.inc, in the order of the page
LOG_CATS = ["dmn", "mgr", "ike", "chd", "job", "cfg", "knl", "net", "asn", "enc", "imc", "imv", "pts", "tls", "esp", "lib"]

IPSEC_SETTINGS_ARGUMENT_SPEC = dict(
    logging=dict(type="dict", options=dict((cat, dict(type="int", choices=LOG_LEVELS)) for cat in LOG_CATS)),
    uniqueids=dict(type="str", choices=["replace", "no", "never", "keep"]),
    filtermode=dict(type="str", choices=["enc", "if_ipsec"]),
    ikev2_retransmit_tries=dict(type="int"),
    ikev2_retransmit_timeout=dict(type="float"),
    ikev2_retransmit_base=dict(type="float"),
    ikev2_retransmit_jitter=dict(type="int"),
    ikev2_retransmit_limit=dict(type="int"),
    compression=dict(type="bool"),
    pkcs11support=dict(type="bool"),
    enableinterfacesuse=dict(type="bool"),
    acceptunencryptedmainmode=dict(type="bool"),
    maxexchange=dict(type="int"),
    unityplugin=dict(type="bool"),
    strictcrlpolicy=dict(type="bool"),
    dns_interval=dict(type="int"),
    makebeforebreak=dict(type="bool"),
    async_crypto=dict(type="bool"),
    port=dict(type="int"),
    port_nat_t=dict(type="int"),
    noshuntlaninterfaces=dict(type="bool"),
    ipsecbypass=dict(type="bool"),
    bypassrules=dict(
        type="list",
        elements="dict",
        no_log=False,
        options=dict(
            source=dict(type="str", required=True),
            destination=dict(type="str", required=True),
        ),
    ),
)

# The fields stored directly in <ipsec>, by option name
FIELDS = dict((param, param.replace("dns_interval", "dns-interval")) for param in IPSEC_SETTINGS_ARGUMENT_SPEC if param not in ["logging", "bypassrules"])
BOOL_PARAMS = [param for param in FIELDS if IPSEC_SETTINGS_ARGUMENT_SPEC[param]["type"] == "bool"]
NUMBER_PARAMS = [param for param in FIELDS if IPSEC_SETTINGS_ARGUMENT_SPEC[param]["type"] in ["int", "float"]]

# The changes after which the page restarts strongSwan instead of reloading it
RESTART_FIELDS = ["compression", "pkcs11support", "enableinterfacesuse", "unityplugin", "acceptunencryptedmainmode", "maxexchange"]

# What the page does after saving its settings
IPSEC_SETTINGS_PHP_COMMAND = """
require_once("filter.inc");
require_once("ipsec.inc");
require_once("vpn.inc");
$retval = 0;
$retval |= filter_configure();
ipsec_configure({restart}, {filterdns_restart});
system_setup_sysctl();
clear_subsystem_dirty('sysctl');
"""


class PFSenseIpsecSettingsModule(PFSenseModuleBase):
    """module managing the IPsec advanced settings"""

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """return argument spec"""
        return IPSEC_SETTINGS_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseIpsecSettingsModule, self).__init__(module, pfsense, name="pfsense_ipsec_settings")
        self.root_elt = self.pfsense.get_element("ipsec", create_node=True)
        self.before = dict()

    ##############################
    # params processing
    #
    def _snapshot(self):
        """the settings stored in <ipsec>, without the tunnels and their keys"""
        values = dict()
        for param, field in FIELDS.items():
            elt = self.root_elt.find(field)
            if elt is not None:
                # A set check box is an empty element
                values[field] = "" if param in BOOL_PARAMS and param != "async_crypto" else (elt.text or "").strip()

        logging = self.root_elt.find("logging")
        if logging is not None:
            values["logging"] = dict((elt.tag, (elt.text or "").strip()) for elt in logging)

        bypassrules = self.root_elt.find("bypassrules")
        if bypassrules is not None:
            rules = [dict((elt.tag, (elt.text or "").strip()) for elt in rule) for rule in bypassrules.findall("rule")]
            values["bypassrules"] = dict(rule=rules) if rules else ""
        return values

    def _subnet_family(self, subnet):
        """is_subnet() of /etc/inc/util.inc: 4 or 6 for a valid address/bits, else None"""
        address, sep, bits = subnet.partition("/")
        if not sep or not re.fullmatch(r"[0-9]{1,3}", bits):
            return None
        if self.pfsense.is_ipv4_address(address):
            return 4 if int(bits) <= 32 else None
        if self.pfsense.is_ipv6_address(address) and "%" not in address:
            return 6 if int(bits) <= 128 else None
        return None

    def _validate_params(self):
        """do the checks of the web GUI on each option"""
        params = self.params

        for param in NUMBER_PARAMS:
            if params.get(param) is not None and params[param] < 0:
                self.module.fail_json(msg="{0} must be 0 or more".format(param))

        maxexchange = params.get("maxexchange")
        if maxexchange and not 3 <= maxexchange <= 64:
            self.module.fail_json(msg="maxexchange must be between 3 and 64")

        for param in ["port", "port_nat_t"]:
            if params.get(param) and params[param] > 65535:
                self.module.fail_json(msg="{0} must be between 1 and 65535".format(param))

        for rule in params.get("bypassrules") or []:
            families = []
            for field in ["source", "destination"]:
                family = self._subnet_family(rule[field])
                if family is None:
                    self.module.fail_json(msg="{0} is not a valid {1} network for an IPsec bypass rule".format(rule[field], field))
                families.append(family)
            if families[0] != families[1]:
                self.module.fail_json(msg="IPsec bypass source and destination addresses must belong to the same address family")

    def _validate_obj(self):
        """do the checks of the web GUI that involve the other settings"""
        obj = self.obj

        ports = [obj.get(field) for field in ["port", "port_nat_t"]]
        if all(port and port.isdigit() for port in ports) and int(ports[0]) == int(ports[1]):
            self.module.fail_json(msg="port and port_nat_t must be different")

        if self.params.get("bypassrules") and "ipsecbypass" not in obj:
            self.module.fail_json(msg="bypassrules requires ipsecbypass")
        if (self.params.get("ipsecbypass") or self.params.get("bypassrules") is not None) and "ipsecbypass" in obj and not obj.get("bypassrules"):
            self.module.fail_json(msg="bypassrules is required with ipsecbypass")

        if "pkcs11support" in self.before and "pkcs11support" not in obj:
            for phase1 in self.root_elt.findall("phase1"):
                if phase1.findtext("authentication_method") == "pkcs11" and phase1.find("disabled") is None:
                    self.module.fail_json(msg="Unable to disable PKCS#11 support, already in use for Phase 1 authentication")

    def _number(self, param, field):
        """the number to store, or the stored one when they are equal"""
        value = self.params[param]
        try:
            if float(self.before[field]) == value:
                return self.before[field]
        except (KeyError, ValueError):
            pass
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        return str(value)

    def _params_to_obj(self):
        """return the settings once changed"""
        params = self.params
        obj = dict(self.before)

        for param, field in FIELDS.items():
            value = params.get(param)
            if value is None:
                continue
            if param == "async_crypto":
                # The page stores "enabled" or "disabled"; nothing stored means disabled
                if value or field in obj:
                    obj[field] = "enabled" if value else "disabled"
            elif param in BOOL_PARAMS:
                if value:
                    obj[field] = ""
                else:
                    obj.pop(field, None)
            elif param in NUMBER_PARAMS:
                # As in pfSense, 0 is the same as nothing stored
                if value:
                    obj[field] = self._number(param, field)
                else:
                    obj.pop(field, None)
            else:
                obj[field] = value

        levels = dict((cat, str(level)) for cat, level in (params.get("logging") or {}).items() if level is not None)
        if levels:
            logging = dict(obj.get("logging") or {})
            logging.update(levels)
            obj["logging"] = dict((cat, logging[cat]) for cat in LOG_CATS if cat in logging)
            obj["logging"].update((cat, level) for cat, level in logging.items() if cat not in LOG_CATS)

        rules = None
        if params.get("ipsecbypass") is False:
            rules = []
        if params.get("bypassrules") is not None:
            rules = []
            for rule in params["bypassrules"]:
                source, dummy, srcmask = rule["source"].partition("/")
                destination, dummy, dstmask = rule["destination"].partition("/")
                rules.append(dict(source=source, srcmask=srcmask, destination=destination, dstmask=dstmask))
        if rules:
            obj["bypassrules"] = dict(rule=rules)
        elif rules is not None and obj.get("bypassrules"):
            # The page leaves an empty element when there is no rule
            obj["bypassrules"] = ""

        return obj

    ##############################
    # XML processing
    #
    def _copy_and_update_target(self):
        """update the settings in <ipsec>"""
        before = self.before
        self.diff["before"] = before
        changed = self.obj != before
        if changed:
            values = dict()
            for field in FIELDS.values():
                if field in self.obj:
                    values[field] = self.obj[field]
                else:
                    self.pfsense.remove_deleted_param_from_elt(self.target_elt, field, self.obj)
            for field in ["logging", "bypassrules"]:
                if field in self.obj:
                    values[field] = self.obj[field]
            self.pfsense.copy_dict_to_element(values, self.target_elt)
        self.diff["after"] = self._snapshot()
        return (before, changed)

    ##############################
    # run
    #
    def run(self, params):
        """process input params to update the settings"""
        self.params = params
        if not any(value is not None and not (isinstance(value, dict) and all(level is None for level in value.values())) for value in params.values()):
            return

        self.target_elt = self.root_elt
        self._validate_params()
        self.before = self._snapshot()
        self.obj = self._params_to_obj()
        self._validate_obj()
        self._add()

    def _update(self):
        """reload IPsec as the page does"""
        before, after = self.diff["before"], self.diff["after"]
        restart = any(before.get(field) != after.get(field) for field in RESTART_FIELDS)
        filterdns_restart = before.get("dns-interval") != after.get("dns-interval")
        return self.pfsense.phpshell(
            IPSEC_SETTINGS_PHP_COMMAND.format(restart="true" if restart else "false", filterdns_restart="true" if filterdns_restart else "false")
        )

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """return obj's name"""
        return "ipsec"

    @staticmethod
    def _log_value(values, param):
        field = FIELDS[param]
        if param == "async_crypto":
            return str(values.get(field) == "enabled")
        if param in BOOL_PARAMS:
            return str(field in values)
        if field not in values:
            return "none"
        return "'{0}'".format(values[field])

    @staticmethod
    def _log_rules(values):
        if not values.get("bypassrules"):
            return "none"
        return "'{0}'".format(
            ", ".join(
                "{0}/{1} to {2}/{3}".format(rule.get("source"), rule.get("srcmask"), rule.get("destination"), rule.get("dstmask"))
                for rule in values["bypassrules"]["rule"]
            )
        )

    def _log_fields(self, before=None):
        """generate pseudo-CLI command fields parameters"""
        after = self.obj
        fields = []
        for param in IPSEC_SETTINGS_ARGUMENT_SPEC:
            if param == "logging":
                old, new = before.get("logging") or {}, after.get("logging") or {}
                for cat in LOG_CATS:
                    if old.get(cat) != new.get(cat):
                        fields.append("logging.{0}='{1}'".format(cat, new[cat]))
            elif param == "bypassrules":
                if self._log_rules(before) != self._log_rules(after):
                    fields.append("bypassrules={0}".format(self._log_rules(after)))
            elif self._log_value(before, param) != self._log_value(after, param):
                fields.append("{0}={1}".format(param, self._log_value(after, param)))
        return ", ".join(fields)


def main():
    module = AnsibleModule(argument_spec=IPSEC_SETTINGS_ARGUMENT_SPEC, supports_check_mode=True)

    pfmodule = PFSenseIpsecSettingsModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
