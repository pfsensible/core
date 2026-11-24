# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2023, Orion Poplwski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase
from ansible_collections.pfsensible.core.plugins.module_utils.rule import PFSenseRuleModule

NAT_PORT_FORWARD_ARGUMENT_SPEC = dict(
    descr=dict(required=True, type="str"),
    state=dict(default="present", choices=["present", "absent"]),
    disabled=dict(default=False, required=False, type="bool"),
    nordr=dict(default=False, required=False, type="bool"),
    interface=dict(required=False, type="str"),
    ipprotocol=dict(default="inet", choices=["inet", "inet6"]),
    protocol=dict(default="tcp", required=False, choices=["tcp", "udp", "tcp/udp", "icmp", "esp", "ah", "gre", "ipv6", "igmp", "pim", "ospf"]),
    source=dict(required=False, type="str"),
    source_port=dict(required=False, type="str"),
    destination=dict(required=False, type="str"),
    destination_port=dict(required=False, type="str"),
    target=dict(required=False, type="str"),
    natreflection=dict(default="system-default", choices=["system-default", "enable", "purenat", "disable"]),
    associated_rule=dict(default="associated", required=False, choices=["associated", "unassociated", "pass", "none"]),
    nosync=dict(default=False, required=False, type="bool"),
    after=dict(required=False, type="str"),
    before=dict(required=False, type="str"),
)

NAT_PORT_FORWARD_REQUIRED_IF = [
    ["state", "present", ["interface", "source", "destination", "target"]]
]

PORT_PROTOCOLS = ("tcp", "udp", "tcp/udp")
NUMERIC_PORTS = re.compile(r"([0-9]{1,5})(?:-([0-9]{1,5}))?")


class PFSenseNatPortForwardModule(PFSenseModuleBase):
    """ module managing pfsense NAT rules """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return NAT_PORT_FORWARD_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseNatPortForwardModule, self).__init__(module, pfsense)
        self.name = "pfsense_nat_port_forward"
        # Override for use with aggregate
        self.argument_spec = NAT_PORT_FORWARD_ARGUMENT_SPEC
        self.obj = dict()

        self.after = None
        self.before = None
        self.position_changed = False
        self.translated_port = ""

        self.root_elt = self.pfsense.get_element("nat")
        if self.root_elt is None:
            self.root_elt = self.pfsense.new_element("nat")
            self.pfsense.root.append(self.root_elt)

        self.pfsense_rule_module = None

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """

        obj = dict()
        self.obj = obj
        obj["descr"] = self.params["descr"]
        if self.params["state"] == "present":
            obj["interface"] = self.pfsense.parse_interface(self.params["interface"])
            if self.pfsense.is_at_least_2_5_0():
                self._get_ansible_param(obj, "ipprotocol")
            self._get_ansible_param(obj, "protocol")
            self._get_ansible_param(obj, "poolopts")
            self._get_ansible_param(obj, "source_hash_key")
            self._get_ansible_param(obj, "natport")

            self._get_ansible_param(obj, "natreflection")
            if obj["natreflection"] == "system-default":
                del obj["natreflection"]

            if self.params["associated_rule"] == "pass":
                obj["associated-rule-id"] = "pass"
            elif self.params["associated_rule"] == "unassociated" and self._find_target() is not None:
                self.module.fail_json(msg="You cannot set an unassociated filter rule if the NAT rule already exists.")
            else:
                obj["associated-rule-id"] = ""

            self._get_ansible_param_bool(obj, "disabled")
            self._get_ansible_param_bool(obj, "nordr")
            self._get_ansible_param_bool(obj, "nosync")

            if "after" in self.params and self.params["after"] is not None:
                self.after = self.params["after"]

            if "before" in self.params and self.params["before"] is not None:
                self.before = self.params["before"]

            obj["source"] = self.pfsense.parse_address(self.params["source"], allow_self=False)
            obj["destination"] = self.pfsense.parse_address(self.params["destination"])
            for address in ("source", "destination"):
                port = self.params.get(address + "_port")
                if port is not None:
                    if self.params["protocol"] not in PORT_PROTOCOLS:
                        self.module.fail_json(msg=f'Cannot specify {address}_port with protocol "{self.params["protocol"]}".')
                    self.pfsense.parse_port(port, obj[address])
            self._parse_target_address(obj)

        return obj

    def _parse_target_address(self, obj):
        """ validate param address field and returns it as a dict """

        if self.params.get("target") is None or self.params["target"] == "":
            self.module.fail_json(msg="The field Redirect target IP is required.")

        param = self.params["target"]
        addr = param.split(":")
        explicit_interface = len(addr) > 1 and addr[0] == "IP"
        if explicit_interface:
            addr = addr[1:]
        if len(addr) > 2 or not addr[0]:
            self.module.fail_json(msg="Cannot parse address %s" % (param))

        address = addr[0]
        ports = addr[1] if len(addr) > 1 else None
        obj["target"] = self._resolve_target_address(address, explicit_interface)
        if obj["target"] is None:
            self.module.fail_json(msg=f'"{param}" is not a valid redirect target IP address, host alias, virtual IP, or interface address.')

        protocol_has_ports = self.params["protocol"] in PORT_PROTOCOLS
        if ports is None:
            if protocol_has_ports:
                self.module.fail_json(msg='Must specify a target port with protocol "{0}".'.format(self.params["protocol"]))
            # pfSense keeps an empty local-port element for protocols without ports.
            obj["local-port"] = self.translated_port = ""
            return

        if not protocol_has_ports:
            self.module.fail_json(msg='Cannot specify a target port with protocol "{0}".'.format(self.params["protocol"]))

        obj["local-port"], self.translated_port = self._parse_target_ports(ports, obj["destination"].get("port", ""))

    def _target_interface_id(self, target):
        """Return the configured interface ID for a pfSense interface address token."""
        if target.endswith("ip") and self.pfsense.is_interface_port(target[:-2]):
            return target[:-2]
        return None

    def _resolve_target_address(self, address, explicit_interface):
        """Resolve a target to the value pfSense stores in the NAT rule."""
        if not explicit_interface:
            if (self._target_interface_id(address) or self.pfsense.is_ipv4_address(address)
                    or self.pfsense.find_alias(address, "host") is not None):
                return address
            vip = self.pfsense.get_virtual_ip_address(address)
            if vip is not None and self.pfsense.is_ipv4_address(vip):
                return vip

        interface = address if self.pfsense.is_interface_port(address) else self.pfsense.get_interface_by_display_name(address)
        if interface is not None:
            return interface + "ip"
        return None

    def _parse_target_ports(self, ports, destination_port):
        """ Return the NAT starting port and the firewall rule's translated ports. """
        target = NUMERIC_PORTS.fullmatch(ports)
        if target is None or target[2] is None:
            if not self.pfsense.is_port_or_alias(ports):
                self.module.fail_json(msg=f'"{ports}" is not a valid redirect target port. It must be a port alias or integer between 1 and 65535.')
            if target is None:
                return ports, ports

        start = int(target[1])
        destination = NUMERIC_PORTS.fullmatch(destination_port)
        end = int(target[2]) if target[2] is not None else None
        if end is not None:
            if not 1 <= start <= end <= 65535:
                self.module.fail_json(msg=f'"{ports}" is not a valid redirect target port range. Use ascending ports between 1 and 65535.')
            if destination is None:
                self.module.fail_json(msg="A redirect target port range requires numeric destination ports.")

        width = int(destination[2]) - int(destination[1]) if destination and destination[2] is not None else 0
        if width < 0:
            self.module.fail_json(msg="The destination port range must be in ascending order.")
        if end is not None and end - start != width:
            self.module.fail_json(msg="The redirect target and destination port ranges must contain the same number of ports.")
        if start + width > 65535:
            self.module.fail_json(msg="The translated port range exceeds port 65535.")

        # pfSense derives the target end from the incoming range and stores only the start.
        first = target[1]
        return first, f"{first}-{start + width}" if width else first

    def _validate_params(self):
        """ do some extra checks on input parameters """

        if self.params.get("after") and self.params.get("before"):
            self.module.fail_json(msg="Cannot specify both after and before")
        elif self.params.get("after"):
            if self.params["after"] == self.params["descr"]:
                self.module.fail_json(msg="Cannot specify the current rule in after")
        elif self.params.get("before"):
            if self.params["before"] == self.params["descr"]:
                self.module.fail_json(msg="Cannot specify the current rule in before")

    ##############################
    # XML processing
    #
    def _build_associated_rule_params(self):
        params = dict()
        params["name"] = "NAT " + self.params["descr"]
        params["state"] = "present"
        params["action"] = "pass"
        if self.pfsense.is_at_least_2_5_0():
            params["ipprotocol"] = self.obj.get("ipprotocol", "inet")
        params["statetype"] = "keep state"
        params["interface"] = self.params["interface"]
        params["source"] = self.params["source"]
        # A NAT rule with no source port must also clear its associated rule's source port.
        params["source_port"] = self.params.get("source_port") if "port" in self.obj["source"] else ""
        target = self.obj["target"]
        interface = self._target_interface_id(target)
        params["destination"] = f"IP:{interface}" if interface is not None else target
        if self.translated_port:
            params["destination"] += ":" + self.translated_port
        params["disabled"] = self.params["disabled"]
        params["protocol"] = self.params["protocol"]
        return params

    def _copy_and_add_target(self):
        """ create the XML target_elt """
        self._set_associated_rule()
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff["after"] = self.pfsense.element_to_dict(self.target_elt)
        self._insert(self.target_elt)

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff["before"] = before
        changed = self._set_associated_rule(before)

        if self.pfsense.copy_dict_to_element(self.obj, self.target_elt):
            changed = True

        if self._remove_deleted_params():
            changed = True

        if self._update_rule_position(self.target_elt):
            changed = True

        self.diff["after"] = self.pfsense.element_to_dict(self.target_elt)
        return (before, changed)

    def _create_associated_rule(self):
        if self.pfsense_rule_module is None:
            self.pfsense_rule_module = PFSenseRuleModule(self.module, self.pfsense)
        params = self._build_associated_rule_params()
        if self.params["associated_rule"] == "associated":
            params["associated-rule-id"] = self.pfsense.uniqid("nat_", True)
            self.obj["associated-rule-id"] = params["associated-rule-id"]
        self.pfsense_rule_module.result["changed"] = False
        self.pfsense_rule_module.result["commands"] = list()
        self.pfsense_rule_module.run(params)
        self.result["commands"] += self.pfsense_rule_module.result["commands"]

    def _create_target(self):
        """ create the XML target_elt """
        target_elt = self.pfsense.new_element("rule")
        return target_elt

    def _delete_associated_rule(self, ruleid, interface):
        if ruleid is None or ruleid == "" or ruleid == "pass":
            return

        self.pfsense_rule_module = PFSenseRuleModule(self.module, self.pfsense)
        params = dict()
        if self.params["descr"] is None:
            params["name"] = "NAT "
        else:
            params["name"] = "NAT " + self.params["descr"]
        params["interface"] = interface
        params["state"] = "absent"
        params["associated-rule-id"] = ruleid
        self.pfsense_rule_module.run(params)
        self.result["commands"] += self.pfsense_rule_module.result["commands"]

    def _find_rule_by_descr(self, descr):
        """ find the XML target_elt """
        for idx, rule_elt in enumerate(self.root_elt):
            if rule_elt.tag != "rule":
                continue

            if rule_elt.find("descr").text == descr:
                return (rule_elt, idx)
        return (None, None)

    def _find_target(self):
        """ find the XML target_elt """
        for rule_elt in self.root_elt:
            if rule_elt.tag != "rule":
                continue

            if rule_elt.find("descr").text == self.obj["descr"]:
                return rule_elt
        return None

    def _get_expected_rule_position(self):
        """ get expected rule position in interface/floating """
        if self.before == "bottom":
            return len(self.root_elt)
        elif self.after == "top":
            return 0
        elif self.after is not None:
            return self._get_rule_position(self.after) + 1
        elif self.before is not None:
            position = self._get_rule_position(self.before) - 1
            if position < 0:
                return 0
            return position
        else:
            position = self._get_rule_position(self.after, fail=False)
            if position is not None:
                return position
            return len(self.root_elt)
        return -1

    def _get_expected_rule_xml_index(self):
        """ get expected rule index in xml """
        if self.before == "bottom":
            return len(self.root_elt)
        elif self.after == "top":
            return 0
        elif self.after is not None:
            found, i = self._find_rule_by_descr(self.after)
            if found is not None:
                return i + 1
            else:
                self.module.fail_json(msg="Failed to insert after rule=%s" % (self.after))
        elif self.before is not None:
            found, i = self._find_rule_by_descr(self.before)
            if found is not None:
                return i
            else:
                self.module.fail_json(msg="Failed to insert before rule=%s" % (self.before))
        else:
            found, i = self._find_rule_by_descr(self.obj["descr"])
            if found is not None:
                return i
            return len(self.root_elt)
        return -1

    @staticmethod
    def _get_params_to_remove():
        """ returns the list of params to remove if they are not set """
        return ["disabled", "nordr", "nosync", "natreflection"]

    def _get_rule_position(self, descr=None, fail=True):
        """ get rule position in interface/floating """
        if descr is None:
            descr = self.obj["descr"]

        (res, idx) = self._find_rule_by_descr(descr)
        if fail and res is None:
            self.module.fail_json(msg="Failed to find rule=%s" % (descr))
        return idx

    def _insert(self, rule_elt):
        """ insert rule into xml """
        rule_xml_idx = self._get_expected_rule_xml_index()
        self.root_elt.insert(rule_xml_idx, rule_elt)

    def _pre_remove_target_elt(self):
        """ processing before removing elt """
        ruleid_elt = self.target_elt.find("associated-rule-id")
        if ruleid_elt is not None:
            self._delete_associated_rule(ruleid_elt.text, self.target_elt.findtext("interface"))

    def _set_associated_rule(self, before=None):
        """ manage changes to the associated rule """
        if before is None:
            if self.params["associated_rule"] == "associated" or self.params["associated_rule"] == "unassociated":
                self._create_associated_rule()
        else:
            before_rule_id = before.get("associated-rule-id") or ""
            if self.params["associated_rule"] == "associated":
                if before_rule_id.startswith("nat_"):
                    if self.obj["interface"] != before["interface"]:
                        self._delete_associated_rule(before_rule_id, before["interface"])
                    else:
                        self.obj["associated-rule-id"] = before_rule_id
                        self._update_associated_rule(before_rule_id)
                        return False
                self._create_associated_rule()
            elif before_rule_id.startswith("nat_"):
                self._delete_associated_rule(before_rule_id, before["interface"])
        return False

    def _update_associated_rule(self, ruleid):
        if self.pfsense_rule_module is None:
            self.pfsense_rule_module = PFSenseRuleModule(self.module, self.pfsense)
        params = self._build_associated_rule_params()
        params["associated-rule-id"] = ruleid
        self.pfsense_rule_module.result["changed"] = False
        self.pfsense_rule_module.result["commands"] = list()
        self.pfsense_rule_module.run(params)
        self.result["commands"] += self.pfsense_rule_module.result["commands"]
        if self.pfsense_rule_module.result["changed"]:
            self.result["changed"] = True
            self.change_descr = "ansible {0} updated {1}".format(self._get_module_name(), self._get_obj_name())

    def _update_rule_position(self, rule_elt):
        """ move rule in xml if required """
        current_position = self._get_rule_position()
        expected_position = self._get_expected_rule_position()
        if current_position == expected_position:
            self.position_changed = False
            return False

        self.diff["before"]["position"] = current_position
        self.diff["after"]["position"] = expected_position
        self.root_elt.remove(rule_elt)
        self._insert(rule_elt)
        self.position_changed = True
        return True

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell("""require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('natconf'); clear_subsystem_dirty('filter'); }""")

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}'".format(self.obj["descr"])

    @staticmethod
    def fassociate(value):
        """ associated-rule-id value formatting function """
        if value is None or value == "":
            return "none"

        if value == "pass":
            return "pass"

        return "associated"

    @staticmethod
    def fnatreflection(value):
        """ natreflection value formatting function """
        if value is None or value == "none":
            return "'system-default'"

        return value

    @staticmethod
    def fprotocol(value):
        """ protocol value formatting function """
        if value is None or value == "none":
            return "any"

        return value

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ""
        if before is None:
            values += self.format_cli_field(self.params, "disabled", fvalue=self.fvalue_bool, default=False)
            values += self.format_cli_field(self.params, "nordr", fvalue=self.fvalue_bool, default=False)
            values += self.format_cli_field(self.params, "interface")
            if self.pfsense.is_at_least_2_5_0():
                values += self.format_cli_field(self.params, "ipprotocol", default="inet")
            values += self.format_cli_field(self.params, "protocol", default="tcp")
            values += self.format_cli_field(self.params, "source")
            values += self.format_cli_field(self.params, "source_port")
            values += self.format_cli_field(self.params, "destination")
            values += self.format_cli_field(self.params, "destination_port")
            values += self.format_cli_field(self.params, "target")
            values += self.format_cli_field(self.params, "natreflection", default="system-default")
            values += self.format_cli_field(self.params, "associated_rule", default="associated")
            values += self.format_cli_field(self.params, "nosync", fvalue=self.fvalue_bool, default=False)
            values += self.format_cli_field(self.params, "after")
            values += self.format_cli_field(self.params, "before")
        else:
            fbefore = self._obj_to_log_fields(before)
            fafter = self._obj_to_log_fields(self.obj)
            fafter["before"] = self.before
            fafter["after"] = self.after

            values += self.format_updated_cli_field(self.obj, before, "disabled", fvalue=self.fvalue_bool, default=False, add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "nordr", fvalue=self.fvalue_bool, default=False, add_comma=(values))
            values += self.format_updated_cli_field(fafter, fbefore, "interface", add_comma=(values))
            if self.pfsense.is_at_least_2_5_0():
                values += self.format_updated_cli_field(self.obj, before, "ipprotocol", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "protocol", fvalue=self.fprotocol, add_comma=(values))
            values += self.format_updated_cli_field(fafter, fbefore, "source", add_comma=(values))
            values += self.format_updated_cli_field(fafter, fbefore, "source_port", add_comma=(values))
            values += self.format_updated_cli_field(fafter, fbefore, "destination", add_comma=(values))
            values += self.format_updated_cli_field(fafter, fbefore, "destination_port", add_comma=(values))
            values += self.format_updated_cli_field(fafter, fbefore, "target", add_comma=(values))
            values += self.format_updated_cli_field(
                self.obj, before, "natreflection", fvalue=self.fnatreflection, default="system-default", add_comma=(values)
            )
            values += self.format_updated_cli_field(self.obj, before, "associated-rule-id", fvalue=self.fassociate, fname="associated_rule", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "nosync", fvalue=self.fvalue_bool, default=False, add_comma=(values))
            if self.position_changed:
                values += self.format_updated_cli_field(fafter, {}, "after", log_none=False, add_comma=(values))
                values += self.format_updated_cli_field(fafter, {}, "before", log_none=False, add_comma=(values))

        return values

    def _obj_address_to_log_field(self, address, include_port):
        """ return formated address from dict """
        if not isinstance(address, dict):
            return address

        field = "!" if "not" in address else ""
        if "any" in address:
            field += "any"
        elif "address" in address:
            field += address["address"]
        elif "network" in address:
            network = address["network"]
            interface = self.pfsense.get_interface_display_name(network[:-2], return_none=True) if network.endswith("ip") else None
            if interface is not None:
                field += "IP:" + interface
            else:
                field += "NET:" + self.pfsense.get_interface_display_name(network)
        if include_port and address.get("port"):
            field += ":" + address["port"] if field else address["port"]
        return field

    def _obj_to_log_fields(self, rule):
        """ return formated source and destination from dict """
        res = {}
        for address in ("source", "destination"):
            port_arg = address + "_port"
            separate_port = self.params.get(port_arg) is not None
            res[address] = self._obj_address_to_log_field(rule[address], include_port=not separate_port)
            if separate_port and isinstance(rule[address], dict):
                res[port_arg] = rule[address].get("port")
        res["target"] = rule["target"]
        if "local-port" in rule:
            res["target"] += ":" + rule["local-port"]
        res["interface"] = self.pfsense.get_interface_display_name(rule["interface"])

        return res
