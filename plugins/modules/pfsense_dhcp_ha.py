#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Romain Tiennot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_dhcp_ha

short_description: Manage the high availability of the Kea DHCP server

version_added: "0.8.0"

description:
  - Manage the High Availability section of Services > DHCP Server > Settings, or of Services > DHCPv6 Server > Settings with
    O(ipprotocol=inet6). Two Kea DHCP servers run in hot-standby and share their leases.
  - Omitted options preserve existing settings.
  - As the Apply button of the page does, the DHCP server is reconfigured after a change.

notes:
  - The Kea DHCP backend only (System > Advanced > Networking).
  - On an HA pair, the configuration sync of the primary (System > High Availability, DHCP Server settings) copies these settings to
    the secondary, with the role, the addresses and the ports swapped, and its local name as the remote name of the secondary. It
    does not copy O(localname), O(tls), O(scert), O(mutualtls) and O(ccert), which are set on each node.

options:
  ipprotocol:
    description: The DHCP server, V(inet) for DHCPv4 or V(inet6) for DHCPv6.
    type: str
    choices: [inet, inet6]
    default: inet
  enable:
    description:
      - Enable high availability.
      - Disabling it also removes O(role), as the web GUI does. The other settings are kept.
    type: bool
  role:
    description:
      - Role of this node. Only one node is the primary.
      - pfSense uses V(primary) when none is stored.
    type: str
    choices: [primary, standby]
  localname:
    description:
      - Name of this node, hostname-like. pfSense uses the system hostname when none is stored.
      - An empty string removes it.
    type: str
  localip:
    description:
      - Address of this node, IPv4 or IPv6, which the peer connects to.
      - Required to enable high availability.
    type: str
  localport:
    description: Port this node listens on for its peer. pfSense uses 8765 when none is stored.
    type: int
  remotename:
    description:
      - Name of the peer, its local name.
      - Required to enable high availability.
    type: str
  remoteip:
    description:
      - Address of the peer, IPv4 or IPv6.
      - Required to enable high availability.
    type: str
  remoteport:
    description: Port of the peer. pfSense uses 8765 when none is stored.
    type: int
  heartbeatdelay:
    description: Time between two heartbeats, in milliseconds. pfSense uses 10000 when none is stored.
    type: int
  maxresponsedelay:
    description:
      - Time without an answer from the peer after which it is deemed offline, in milliseconds.
      - pfSense uses 60000 when none is stored.
    type: int
  maxackdelay:
    description:
      - Time after which a client the peer did not answer counts as unacknowledged, in milliseconds.
      - pfSense uses 60000 when none is stored.
    type: int
  maxunackedclients:
    description:
      - Number of unacknowledged clients after which the peer is deemed offline. With V(0), it is deemed offline as soon as it stops
        answering.
      - pfSense uses 0 when none is stored.
    type: int
  maxrejectedleaseupdates:
    description:
      - Number of lease updates the peer may reject before this node stops serving. V(0) means no limit.
      - pfSense uses 10 when none is stored.
    type: int
  tls:
    description:
      - Encrypt the communication between the nodes with TLS.
      - Disabling it also removes O(scert), O(mutualtls) and O(ccert).
    type: bool
  scert:
    description:
      - Certificate this node presents as a server, by its description. Its CA chain is also the one that checks the certificate of
        the peer, so both nodes need certificates from the same CA.
      - Required with O(tls).
    type: str
  mutualtls:
    description:
      - Present a client certificate to the peer, and require one from it.
      - Disabling it also removes O(ccert).
    type: bool
  ccert:
    description:
      - Client certificate of this node, by its description.
      - Required with O(mutualtls).
    type: str

author: Romain Tiennot (@RomainTie)
"""

EXAMPLES = r"""
- name: Make this node the primary of a DHCP HA pair
  pfsensible.core.pfsense_dhcp_ha:
    enable: true
    role: primary
    localip: 192.168.4.1
    remotename: fw2
    remoteip: 192.168.4.2
    tls: true
    scert: DHCP HA

# The configuration sync brings the rest from the primary
- name: Choose the certificate of the secondary
  pfsensible.core.pfsense_dhcp_ha:
    tls: true
    scert: DHCP HA

- name: Disable the DHCPv6 high availability
  pfsensible.core.pfsense_dhcp_ha:
    ipprotocol: inet6
    enable: false
"""

RETURN = r"""
commands:
    description: Pseudo-CLI commands describing configuration changes.
    returned: always
    type: list
    elements: str
    sample: ["update dhcp_ha kea set enable=True, role='primary', localip='192.168.4.1'"]
"""

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

DHCP_HA_ARGUMENT_SPEC = dict(
    ipprotocol=dict(type="str", choices=["inet", "inet6"], default="inet"),
    enable=dict(type="bool"),
    role=dict(type="str", choices=["primary", "standby"]),
    localname=dict(type="str"),
    localip=dict(type="str"),
    localport=dict(type="int"),
    remotename=dict(type="str"),
    remoteip=dict(type="str"),
    remoteport=dict(type="int"),
    heartbeatdelay=dict(type="int"),
    maxresponsedelay=dict(type="int"),
    maxackdelay=dict(type="int"),
    maxunackedclients=dict(type="int"),
    maxrejectedleaseupdates=dict(type="int"),
    tls=dict(type="bool"),
    scert=dict(type="str"),
    mutualtls=dict(type="bool"),
    ccert=dict(type="str"),
)

# The fields of <kea><ha> (<kea6><ha>), in the order of the page
FIELDS = ["enable", "role", "localname", "localip", "localport", "remotename", "remoteip", "remoteport", "heartbeatdelay",
          "maxresponsedelay", "maxackdelay", "maxunackedclients", "maxrejectedleaseupdates", "tls", "scertref", "mutualtls", "ccertref"]
BOOL_FIELDS = ["enable", "tls", "mutualtls"]
INT_FIELDS = ["heartbeatdelay", "maxresponsedelay", "maxackdelay", "maxunackedclients", "maxrejectedleaseupdates"]
CERT_FIELDS = dict(scert="scertref", ccert="ccertref")

# is_domain() of /etc/inc/util.inc, which is_hostname() uses
HOSTNAME_RE = re.compile(r"^(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$", re.IGNORECASE)

# What the Apply button of the page does for the DHCP server
DHCP_HA_PHP_COMMAND = """
require_once("services.inc");
services_dhcpd_configure("{family}");
"""


class PFSenseDHCPHAModule(PFSenseModuleConfigBase):
    """ module managing the high availability of the Kea DHCP server """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DHCP_HA_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        family = module.params.get("ipprotocol") or "inet"
        super(PFSenseDHCPHAModule, self).__init__(
            module, pfsense, name="pfsense_dhcp_ha", root="kea6" if family == "inet6" else "kea", node="ha", create_root=True,
            bool_style="absent/present", update_php=DHCP_HA_PHP_COMMAND.format(family=family),
        )

    ##############################
    # params processing
    #
    def _stored(self, field):
        ha = self.root_elt.find(self.node)
        return ha.findtext(field) if ha is not None else None

    def _wanted(self, field):
        """ the value the field will have: the parameter when given, else the stored one """
        param = {"scertref": "scert", "ccertref": "ccert"}.get(field, field)
        value = self.params.get(param)
        if value is None:
            return self._stored(field)
        if field in BOOL_FIELDS:
            return "" if value else None
        return str(value)

    def _certref(self, name, param):
        cert = self.pfsense.find_cert_elt(name)
        if cert is None:
            self.module.fail_json(msg="{0}: certificate '{1}' not found".format(param, name))
        if not cert.findtext("prv"):
            self.module.fail_json(msg="{0}: certificate '{1}' has no private key".format(param, name))
        return cert.findtext("refid")

    def _validate_params(self):
        """ do the checks of the web GUI, on the settings once changed """
        params = self.params

        for field in ["localname", "remotename"]:
            name = (params.get(field) or "").strip()
            if name and not HOSTNAME_RE.match(name):
                self.module.fail_json(msg="{0} must be hostname-like".format(field))

        for field in ["localip", "remoteip"]:
            address = params.get(field)
            if address is not None and not (self.pfsense.is_ipv4_address(address) or self.pfsense.is_ipv6_address(address)):
                self.module.fail_json(msg="{0} must be a valid IPv4 or IPv6 address".format(field))

        for field in ["localport", "remoteport"]:
            port = params.get(field)
            if port is not None and not 1 <= port <= 65535:
                self.module.fail_json(msg="{0} must be between 1 and 65535".format(field))

        for field in INT_FIELDS:
            if params.get(field) is not None and params[field] < 0:
                self.module.fail_json(msg="{0} must be 0 or more".format(field))

        if params.get("enable") is not False and self._wanted("enable") is not None:
            for field in ["localip", "remotename", "remoteip"]:
                if not (self._wanted(field) or "").strip():
                    self.module.fail_json(msg="{0} is required to enable high availability".format(field))

        if params.get("tls") is not False and self._wanted("tls") is not None and not self._wanted("scertref"):
            self.module.fail_json(msg="scert is required with tls")
        if params.get("tls") is not False and params.get("mutualtls") is not False and self._wanted("mutualtls") is not None:
            if self._wanted("tls") is None:
                self.module.fail_json(msg="mutualtls requires tls")
            if not self._wanted("ccertref"):
                self.module.fail_json(msg="ccert is required with mutualtls")

    def _params_to_obj(self):
        """ return a dict from module params """
        obj = super(PFSenseDHCPHAModule, self)._params_to_obj()
        obj.pop("ipprotocol", None)

        for param, field in CERT_FIELDS.items():
            obj.pop(param, None)
            if self.params.get(param) is not None:
                obj[field] = self._certref(self.params[param], param)

        for field in self._get_params_to_remove():
            obj.pop(field, None)

        return obj

    def _get_params_to_remove(self):
        """ the fields the web GUI removes along with an option """
        to_remove = super(PFSenseDHCPHAModule, self)._get_params_to_remove()
        if self.params.get("enable") is False:
            to_remove.append("role")
        if self.params.get("tls") is False:
            to_remove += ["scertref", "mutualtls", "ccertref"]
        if self.params.get("mutualtls") is False:
            to_remove.append("ccertref")
        if self.params.get("localname") is not None and not self.params["localname"].strip():
            to_remove.append("localname")
        return to_remove

    def run(self, params):
        if any(value is not None for param, value in params.items() if param != "ipprotocol"):
            super(PFSenseDHCPHAModule, self).run(params)

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return self.root

    def _cert_name(self, refid):
        cert = self.pfsense.find_cert_elt(refid, search_field="refid") if refid else None
        return cert.findtext("descr") if cert is not None else refid

    def _log_value(self, values, field):
        if field in BOOL_FIELDS:
            return "True" if field in values else "False"
        if field not in values or values[field] is None:
            return "none"
        value = values[field]
        if field in CERT_FIELDS.values():
            value = self._cert_name(value)
        return "'{0}'".format(value.replace("'", "\\'"))

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters """
        after = self.diff["after"] if before is not None else self.obj
        fields = []
        for field in FIELDS:
            if before is not None and self._log_value(before, field) == self._log_value(after, field):
                continue
            if before is None and field not in after:
                continue
            name = {"scertref": "scert", "ccertref": "ccert"}.get(field, field)
            fields.append("{0}={1}".format(name, self._log_value(after, field)))
        return ", ".join(fields) if before is not None else "".join(", " + field for field in fields)


def main():
    module = AnsibleModule(
        argument_spec=DHCP_HA_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseDHCPHAModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
