#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_nat_1to1

short_description: Manage pfSense NAT 1:1 rules

version_added: "0.8.0"

description:
  - Manage pfSense NAT 1:1 rules.

options:
  descr:
    description: The name of the NAT rule. It must be unique across all interfaces.
    required: true
    type: str
  state:
    description: State in which to leave the NAT rule.
    default: present
    choices: ['present', 'absent']
    type: str
  interface:
    description: The interface where translation takes place, specified by its identifier or display name.
    default: wan
    type: str
  ipprotocol:
    description: The address family of the rule. Use V(inet) for IPv4 or V(inet6) for IPv6.
    default: inet
    choices: ['inet', 'inet6']
    type: str
  external:
    description:
      - The external IP address, or V(IP:<interface>) to use an interface address.
      - For a subnet mapping, specify the external network address. The prefix length comes from O(source).
      - Required when O(state=present).
    type: str
  destination:
    description:
      - Restrict the remote peer to an IP address, CIDR subnet, address alias, interface address, or interface subnet.
      - Use V(IP:<interface>) for an interface address or V(NET:<interface>) for an interface subnet.
      - Prefix the value with C(!) to invert the match.
    default: any
    type: str
  source:
    description:
      - Internal IP address or CIDR subnet to translate, or an interface address or subnet using V(IP:<interface>) or V(NET:<interface>).
      - Use V(any) to match any source in a rule with O(nobinat=true).
      - Prefix the value with C(!) to invert the match.
      - Required when O(state=present).
    type: str
  disabled:
    description: Disable the rule.
    default: false
    type: bool
  nobinat:
    description: Exclude matching traffic from 1:1 translation by subsequent rules.
    default: false
    type: bool
  natreflection:
    description: Override the global 1:1 NAT reflection setting.
    default: system-default
    choices: [system-default, enable, disable]
    type: str

notes:
  - Manage any required inbound firewall rules separately, using the internal address as the firewall rule destination.

author: Orion Poplawski (@opoplawski)
"""

EXAMPLES = r"""
- name: Map a public address to a web server
  pfsensible.core.pfsense_nat_1to1:
    descr: Web Server
    interface: wan
    ipprotocol: inet
    external: 192.0.2.212
    source: 192.168.183.87
    state: present

- name: Map an entire subnet
  pfsensible.core.pfsense_nat_1to1:
    descr: Private subnet
    external: 198.51.100.0
    source: 192.168.20.0/24

- name: Remove Web Server NAT rule
  pfsensible.core.pfsense_nat_1to1:
    descr: Web Server
    state: absent
"""
RETURN = r"""
commands:
    description: The changes expressed as pseudo-CLI commands.
    returned: always
    type: list
    elements: str
    sample: ["delete nat_1to1 'Web Server'"]
"""

from ipaddress import ip_address, ip_network

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

NAT_1TO1_ARGUMENT_SPEC = dict(
    descr=dict(required=True, type="str"),
    state=dict(type="str", default="present", choices=["present", "absent"]),
    interface=dict(type="str", default="wan"),
    ipprotocol=dict(type="str", choices=["inet", "inet6"], default="inet"),
    external=dict(type="str"),
    destination=dict(type="str", default="any"),
    source=dict(type="str"),
    disabled=dict(type="bool", default=False),
    nobinat=dict(type="bool", default=False),
    natreflection=dict(type="str", default="system-default", choices=["system-default", "enable", "disable"]),
)

NAT_1TO1_REQUIRED_IF = [
    ["state", "present", ["external", "source"]],
]

NAT_1TO1_PHP_COMMAND_SET = r"""
require_once("filter.inc");
if (filter_configure() == 0) {
    clear_subsystem_dirty('natconf');
    clear_subsystem_dirty('filter');
}
"""


class PFSenseNat1to1Module(PFSenseModuleBase):
    """Manage pfSense NAT 1:1 rules."""

    @staticmethod
    def get_argument_spec():
        """return argument spec"""
        return NAT_1TO1_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseNat1to1Module, self).__init__(
            module,
            pfsense,
            name="pfsense_nat_1to1",
            root="nat",
            create_root=True,
            node="onetoone",
            update_php=NAT_1TO1_PHP_COMMAND_SET,
            bool_style="absent/present",
        )

    def _find_target(self):
        # Compare descriptions literally, including names containing quotes.
        descr = self.obj["descr"]
        matches = [rule for rule in self.root_elt.findall(self.node) if rule.findtext("descr") == descr]
        if len(matches) > 1:
            self.module.fail_json(msg=f"Found multiple 1:1 NAT rules with description {descr!r}.")
        return matches[0] if matches else None

    def _validate_params(self):
        if not (self.params["descr"] or "").strip():
            self.module.fail_json(msg="descr must contain a rule name.")
        for name, spec in self.argument_spec.items():
            if self.params[name] is None and "default" in spec:
                self.params[name] = spec["default"]
        if self.params["state"] == "present":
            for name in ("source", "external"):
                if self.params[name] is None:
                    self.module.fail_json(msg=f"{name} is required when state is present.")

    def _check_family(self, name, address):
        ipprotocol = self.params["ipprotocol"]
        if address.version != (4 if ipprotocol == "inet" else 6):
            self.module.fail_json(msg=f"{name} must use the address family selected by ipprotocol ({ipprotocol}).")

    def _parse_external(self, value):
        value = value.strip()
        if value.startswith("IP:") and value.count(":") == 1:
            interface = self.pfsense.parse_interface(value[3:])
            return interface + "ip"
        try:
            address = ip_address(value)
            if "%" in value:
                raise ValueError()
        except ValueError:
            self.module.fail_json(msg="external must be an IP address or an IP:<interface> reference.")
        self._check_family("external", address)
        return str(address)

    def _parse_match(self, name, value):
        value = value.strip()
        inverted = value.startswith("!")
        address = value[1:].strip() if inverted else value
        if not address or "%" in address or address.startswith("!"):
            self.module.fail_json(msg=f"{name} must specify a valid address.")

        try:
            network = ip_network(address, strict=False)
        except ValueError:
            # Address matching supports interface references, but 1:1 rules have no ports.
            if ":" in address and not (address.startswith(("IP:", "NET:")) and address.count(":") == 1):
                self.module.fail_json(msg=f"{name} must specify an address without a port.")
            result = self.pfsense.parse_address(address, allow_self=(name == "destination"))
            if "address" in result:
                # The shared parser also resolves virtual IP descriptions.
                try:
                    resolved = ip_address(result["address"])
                except ValueError:
                    if name == "source":
                        self.module.fail_json(msg="source must specify an IP address, subnet, or interface reference.")
                else:
                    self._check_family(name, resolved)
            if "any" in result and (inverted or (name == "source" and not self.params["nobinat"])):
                self.module.fail_json(msg=f"{name} cannot use {value!r} for this rule.")
        else:
            self._check_family(name, network)
            if name == "source" and network.prefixlen == 0 and not self.params["nobinat"]:
                self.module.fail_json(msg="source must have a nonzero prefix length for translation.")
            result = {"address": str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)}
        if inverted:
            result["not"] = None
        return result

    def _params_to_obj(self, obj=None):
        obj = super(PFSenseNat1to1Module, self)._params_to_obj(obj)
        if self.params["state"] == "present":
            obj["external"] = self._parse_external(obj["external"])
            for name in ("source", "destination"):
                obj[name] = self._parse_match(name, obj[name])
            if obj["natreflection"] == "system-default":
                del obj["natreflection"]
        return obj

    def _get_params_to_remove(self):
        fields = super(PFSenseNat1to1Module, self)._get_params_to_remove()
        if self.params["natreflection"] == "system-default":
            fields.append("natreflection")
        return fields


def main():
    module = AnsibleModule(argument_spec=NAT_1TO1_ARGUMENT_SPEC, required_if=NAT_1TO1_REQUIRED_IF, supports_check_mode=True)

    pfmodule = PFSenseNat1to1Module(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
