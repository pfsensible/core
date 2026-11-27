#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_softflowd

short_description: Manage pfSense softflowd configuration

version_added: "0.8.0"

description:
  - Manage the configuration of the installed pfSense softflowd package.
  - Omitted options preserve existing settings.
  - An enabled configuration requires at least one interface, a collector address, and a collector port.

requirements:
  - The pfSense softflowd package must be installed.

options:
  enable:
    description:
      - Enable or disable softflowd.
      - Defaults to V(enabled) when creating the configuration.
    choices: [enabled, "off"]
    type: str
  interface:
    description:
      - Assigned pfSense interface names or descriptions, or V(lo0) for loopback.
      - Softflowd runs one instance per interface. The list order determines the flow interface indices, starting at 1.
    type: list
    elements: str
  host:
    description: IPv4 or IPv6 address of the collector.
    type: str
  port:
    description: Collector UDP port number (1 to 65535) or UDP service name as defined on the firewall.
    type: str
  sample:
    description:
      - Packet sampling denominator. Use V(0) to disable sampling.
      - Defaults to V(0) when creating the configuration.
    type: int
  maxflows:
    description: Maximum number of flows to track concurrently. The daemon defaults to 8192.
    type: int
  hoplimit:
    description:
      - IPv4 TTL or IPv6 hop limit, from 1 to 255.
      - The daemon uses the system default for unicast and 1 for multicast when this setting is unset.
    type: int
  version:
    description:
      - Export protocol version. V(10) selects IPFIX.
      - Defaults to V(10) when creating the configuration.
    choices: [psamp, "10", "9", "5", "1"]
    type: str
  biflows:
    description: Use bidirectional flows. Requires version V(10). Disabled when creating the configuration unless requested.
    type: bool
  flowtracking:
    description:
      - Flow fields to track. V(ip) tracks source and destination addresses.
      - V(proto) adds the protocol, V(full) adds transport ports, and V(vlan) adds the VLAN ID.
      - V(ether) adds source and destination MAC addresses to V(vlan) and is the default when creating the configuration.
    choices: [ether, vlan, full, proto, ip]
    type: str
  flowtimestamp:
    description:
      - Timestamp precision for reported flows. V(omit) uses the system boot time in place of the actual flow start and end times.
      - Defaults to V(sec) when creating the configuration.
    choices: [sec, milli, micro, nano, omit]
    type: str
  timeout_general:
    description: Positive timeout in seconds for traffic without a more specific timeout.
    type: int
  timeout_maxlife:
    description: Maximum flow lifetime in seconds. Use V(0) to disable the lifetime limit.
    type: int
  timeout_expint:
    description: Interval between expiry checks in seconds. Use V(0) to disable the interval.
    type: int
  timeout_tcp:
    description: Timeout in seconds for open TCP connections.
    type: int
  timeout_tcp_rst:
    description: Timeout in seconds after either TCP endpoint sends a reset.
    type: int
  timeout_tcp_fin:
    description: Timeout in seconds after both TCP endpoints send a FIN.
    type: int
  timeout_udp:
    description: Timeout in seconds for UDP flows.
    type: int

author: Orion Poplawski (@opoplawski)
"""

EXAMPLES = r"""
- name: Export LAN flows to a collector
  pfsensible.core.pfsense_softflowd:
    interface:
      - lan
    host: 192.0.2.10
    port: "2055"
    version: "10"
    flowtracking: full

- name: Disable softflowd while retaining its configuration
  pfsensible.core.pfsense_softflowd:
    enable: "off"
"""

RETURN = r"""
commands:
    description: Pseudo-CLI commands describing configuration changes.
    returned: always
    type: list
    elements: str
    sample: ["update softflowd softflowd set enable='off'"]
"""

import re
from ipaddress import ip_address
from socket import getservbyname

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

SOFTFLOWD_ARGUMENT_SPEC = dict(
    enable=dict(type="str", choices=["enabled", "off"]),
    interface=dict(type="list", elements="str"),
    host=dict(type="str"),
    port=dict(type="str"),
    sample=dict(type="int"),
    maxflows=dict(type="int"),
    hoplimit=dict(type="int"),
    version=dict(type="str", choices=["psamp", "10", "9", "5", "1"]),
    biflows=dict(type="bool"),
    flowtracking=dict(type="str", choices=["ether", "vlan", "full", "proto", "ip"]),
    flowtimestamp=dict(type="str", choices=["sec", "milli", "micro", "nano", "omit"]),
    timeout_general=dict(type="int"),
    timeout_maxlife=dict(type="int"),
    timeout_expint=dict(type="int"),
    timeout_tcp=dict(type="int"),
    timeout_tcp_rst=dict(type="int"),
    timeout_tcp_fin=dict(type="int"),
    timeout_udp=dict(type="int"),
)

TIMEOUT_FIELDS = {name: name.replace("_", "-") for name in SOFTFLOWD_ARGUMENT_SPEC if name.startswith("timeout_")}

SOFTFLOWD_CREATE_DEFAULT = {
    "enable": "enabled",
    "interface": "",
    "host": "",
    "port": "",
    "sample": "0",
    "maxflows": "",
    "hoplimit": "",
    "version": "10",
    "biflows": "",
    "flowtracking": "ether",
    "flowtimestamp": "sec",
    **dict.fromkeys(TIMEOUT_FIELDS.values(), ""),
}

SOFTFLOWD_PHP_COMMAND_SET = """
require_once("/usr/local/pkg/softflowd.inc");
sync_package_softflowd();
"""


def parse_interfaces(pfmodule, name, params, obj):
    interfaces = []
    for value in params[name]:
        if value.lower() in ("lo0", "loopback"):
            interface = "lo0"
        else:
            interface = pfmodule.pfsense.parse_interface(value, with_virtual=False)
            if not pfmodule.pfsense.is_interface_port(interface):
                pfmodule.module.fail_json(msg=f"{value} must be an assigned interface or lo0")
        if interface in interfaces:
            pfmodule.module.fail_json(msg=f"Duplicate softflowd interface: {interface}")
        interfaces.append(interface)
    # The package assigns export indices in this order.
    obj[name] = ",".join(interfaces)


class PFSenseSoftflowdModule(PFSenseModuleConfigBase):
    """Manage the softflowd package settings."""

    @staticmethod
    def get_argument_spec():
        return SOFTFLOWD_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseSoftflowdModule, self).__init__(
            module,
            pfsense,
            name="pfsense_softflowd",
            package="softflowd",
            root="softflowd",
            node="config",
            arg_route={"interface": {"parse": parse_interfaces}},
            map_param=TIMEOUT_FIELDS.items(),
            bool_values={"biflows": ("", "ON")},
            create_root=True,
            create_default=SOFTFLOWD_CREATE_DEFAULT.copy(),
            update_php=SOFTFLOWD_PHP_COMMAND_SET,
        )

    def _validate_params(self):
        host = self.params.get("host")
        if host is not None:
            try:
                literal, separator, scope = host.partition("%")
                address = ip_address(literal)
                if separator and (address.version != 6 or not address.is_link_local or not re.fullmatch(r"[a-zA-Z0-9_.-]+", scope)):
                    raise ValueError
            except ValueError:
                self.module.fail_json(msg="host must be an IPv4 or IPv6 address")
        port = self.params.get("port")
        if port is not None:
            if re.fullmatch(r"[0-9]+", port):
                digits = port.lstrip("0")
                valid_port = 1 <= len(digits) <= 5 and int(digits) <= 65535
            else:
                try:
                    valid_port = bool(re.fullmatch(r"[a-zA-Z0-9_-]+", port)) and getservbyname(port, "udp") > 0
                except OSError:
                    valid_port = False
            if not valid_port:
                self.module.fail_json(msg="port must be a UDP service name or a port number between 1 and 65535")
        hoplimit = self.params.get("hoplimit")
        if hoplimit is not None and not 1 <= hoplimit <= 255:
            self.module.fail_json(msg="hoplimit must be between 1 and 255")
        # The daemon reads these options as signed C integers.
        for field in ("sample", "maxflows", *TIMEOUT_FIELDS):
            value = self.params.get(field)
            minimum = 1 if field == "timeout_general" else 0
            if value is not None and not minimum <= value <= 2147483647:
                self.module.fail_json(msg=f"{field} must be between {minimum} and 2147483647")

    def _params_to_obj(self):
        obj = super(PFSenseSoftflowdModule, self)._params_to_obj()
        if obj.get("enable") != "off":
            missing = [field for field in ("interface", "host", "port") if not obj.get(field)]
            if missing:
                self.module.fail_json(msg="Enabled softflowd requires: " + ", ".join(missing))
        if obj.get("biflows") not in (None, "", "0") and obj.get("version") != "10":
            self.module.fail_json(msg="biflows requires version 10 (IPFIX)")
        return obj

    def _log_fields(self, before=None):
        values = ""
        for param in self.argument_spec:
            field = TIMEOUT_FIELDS.get(param, param)
            if before is None:
                values += self.format_cli_field(self.obj, field, fname=param)
            else:
                values += self.format_updated_cli_field(self.diff["after"], before, field, fname=param, add_comma=bool(values))
        return values


def main():
    module = AnsibleModule(argument_spec=SOFTFLOWD_ARGUMENT_SPEC, supports_check_mode=True)
    pfmodule = PFSenseSoftflowdModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
