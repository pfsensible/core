# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from base64 import b64encode
from ipaddress import ip_address, ip_interface
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


VIP_ARGUMENT_SPEC = dict(
    address=dict(type="str", required=True),
    descr=dict(type="str"),
    state=dict(type="str", default="present", choices=["present", "absent"]),
)
MODE_ARGUMENT_SPEC = {
    "ipalias": dict(interface=dict(type="str")),
    "carp": dict(
        interface=dict(type="str"), vhid=dict(type="int"), password=dict(type="str", no_log=True),
        advbase=dict(type="int", default=1), advskew=dict(type="int", default=0),
    ),
    "proxyarp": dict(interface=dict(type="str"), noexpand=dict(type="bool")),
    "other": dict(noexpand=dict(type="bool")),
}
MODE_SUFFIX = {"ipalias": "alias", "carp": "carp", "proxyarp": "proxy_arp", "other": "other"}
BOUND_MODES = ("ipalias", "carp")
RUNTIME_FIELDS = ("uniqid", "interface", "subnet", "subnet_bits", "vhid", "password", "advbase", "advskew")

APPLY_PHP = """
require_once("interfaces.inc");
require_once("filter.inc");
$change = json_decode(base64_decode("%s"), true);
$vips = function_exists("config_get_path") ? config_get_path("virtualip/vip", []) : ($config["virtualip"]["vip"] ?? []);
$vip = null;
if ($change["current"] !== null) {
    foreach ($vips as $entry) {
        if (($entry["uniqid"] ?? null) === $change["current"]) {
            $vip = $entry;
            break;
        }
    }
    if ($vip === null) {
        exit(1);
    }
}
if ($change["remove"] !== null) {
    interface_vip_bring_down($change["remove"]);
}
if ($vip !== null && $change["configure"]) {
    if ($vip["mode"] === "ipalias") {
        interface_ipalias_configure($vip);
    } elseif ($vip["mode"] === "carp") {
        interface_carp_configure($vip);
        interfaces_sync_setup();
    }
}
foreach ($change["proxy_interfaces"] as $interface) {
    interface_proxyarp_configure($interface);
}
exit(filter_configure() == 0 ? 0 : 1);
"""


def run_virtual_ip(mode):
    """Run the requested VIP module with its mode-specific options."""
    required = {"ipalias": ["interface"], "carp": ["interface", "vhid", "password"], "proxyarp": ["interface"], "other": []}
    module = AnsibleModule(
        argument_spec=dict(VIP_ARGUMENT_SPEC, **MODE_ARGUMENT_SPEC[mode]),
        required_if=[["state", "present", required[mode]]] if required[mode] else [],
        supports_check_mode=True,
    )
    vip = PFSenseVirtualIPModule(module, mode)
    vip.run(module.params)
    vip.commit_changes()


class PFSenseVirtualIPModule(PFSenseModuleBase):
    """Manage one mode in the shared pfSense VIP list."""

    def __init__(self, module, mode):
        super(PFSenseVirtualIPModule, self).__init__(
            module, name="pfsense_virtual_ip_" + MODE_SUFFIX[mode], root="virtualip", create_root=True,
            node="vip", key="subnet",
        )
        self.mode = mode

    def _params_to_obj(self):
        raw_address = self.params["address"]
        try:
            address = ip_interface(raw_address)
        except ValueError:
            self.module.fail_json(msg="address must be an IPv4 or IPv6 address with an optional prefix length")
        if "%" in raw_address or address.ip.is_unspecified or address.ip.is_multicast:
            self.module.fail_json(msg="address must be a valid unicast VIP address")
        if self.mode == "proxyarp" and address.version != 4:
            self.module.fail_json(msg="Proxy ARP requires an IPv4 address")
        network = self.mode not in BOUND_MODES and address.network.prefixlen < address.max_prefixlen
        if network and address.ip != address.network.network_address:
            self.module.fail_json(msg="address must start at the network boundary for a network VIP")
        if self.mode in BOUND_MODES and self.params["state"] == "present" and "/" not in raw_address:
            self.module.fail_json(msg="address must include a prefix length")

        obj = {"subnet": str(address.ip)}
        if self.params["state"] == "absent":
            return obj

        obj.update(mode=self.mode, type="network" if network else "single", subnet_bits=str(address.network.prefixlen))
        if self.mode != "other":
            obj["interface"] = self._interface(self.params["interface"], address.ip)
        else:
            obj["interface"] = ""
        self._get_ansible_param(obj, "descr")

        if self.mode == "carp":
            for field, minimum, maximum in (("vhid", 1, 255), ("advbase", 1, 254), ("advskew", 0, 254)):
                value = self.params[field]
                if not minimum <= value <= maximum:
                    self.module.fail_json(msg=f"{field} must be between {minimum} and {maximum}")
                obj[field] = str(value)
            if not self.params["password"]:
                self.module.fail_json(msg="password must be nonempty")
            obj["password"] = self.params["password"]
        if self.params.get("noexpand") is not None:
            if self.params["noexpand"] and (not network or address.version != 4):
                self.module.fail_json(msg="noexpand applies to IPv4 network VIPs")
            if self.params["noexpand"]:
                obj["noexpand"] = ""
        return obj

    def _interface(self, name, address):
        interface = self.pfsense.parse_interface(name, fail=False, with_virtual=False)
        if self.mode == "ipalias":
            if name.lower() in ("lo0", "localhost"):
                if str(address) in ("127.0.0.1", "::1"):
                    self.module.fail_json(msg="address is already assigned as a primary loopback address")
                return "lo0"
            entry = None
            if name.startswith("_vip"):
                entry = self.pfsense.find_virtual_ip(name[4:], fields=("uniqid",), modes=("carp",))
            if entry is None:
                fields = ("subnet", "descr") if interface is None else ("subnet",)
                entry = self.pfsense.find_virtual_ip(name, fields=fields, modes=("carp",))
            if entry is not None and entry.findtext("uniqid"):
                parent = ip_address(entry.findtext("subnet"))
                if address.version != parent.version:
                    self.module.fail_json(msg="A stacked IP Alias must use the same IP address family as its CARP VIP")
                return "_vip" + entry.findtext("uniqid")
        if interface is None:
            self.module.fail_json(msg=f"{name} is not a valid interface")
        if not self.pfsense.is_interface_port(interface):
            self.module.fail_json(msg="interface must be an assigned pfSense interface")
        for entry in self.pfsense.interfaces:
            if str(address) in (entry.findtext("ipaddr"), entry.findtext("ipaddrv6")):
                self.module.fail_json(msg="address is already assigned as a primary interface address")
        return interface

    def _find_target(self):
        target = None
        present = self.params["state"] == "present"
        for entry in self.elements:
            try:
                subnet = str(ip_address(entry.findtext("subnet")))
            except ValueError:
                continue
            if subnet == self.obj["subnet"]:
                if entry.findtext("mode") != self.mode:
                    if present:
                        self.module.fail_json(msg="address is already configured as a different VIP type")
                    continue
                if target is not None:
                    self.module.fail_json(msg="address matches more than one VIP of this type")
                target = entry
        if present and self.mode == "carp":
            for entry in self.elements:
                if (entry is not target and entry.findtext("mode") == "carp"
                        and entry.findtext("interface") == self.obj["interface"] and entry.findtext("vhid") == self.obj["vhid"]):
                    self.module.fail_json(msg="vhid is already in use on this interface")
        return target

    def _protect_stacked_aliases(self):
        if self.mode == "carp":
            uid = self.target_elt.findtext("uniqid")
            if uid and any(entry.findtext("interface") == "_vip" + uid for entry in self.elements):
                self.module.fail_json(msg="Move or remove the IP Aliases stacked on this CARP VIP first")

    def _copy_and_add_target(self):
        self.obj["uniqid"] = self.pfsense.uniqid()
        super(PFSenseVirtualIPModule, self)._copy_and_add_target()

    def _copy_and_update_target(self):
        if any(self.obj.get(field) != self.target_elt.findtext(field) for field in ("interface", "subnet_bits", "vhid")):
            self._protect_stacked_aliases()
        if not self.target_elt.findtext("uniqid"):
            self.obj["uniqid"] = self.pfsense.uniqid()
        return super(PFSenseVirtualIPModule, self)._copy_and_update_target()

    def _get_params_to_remove(self):
        return ["noexpand"] if self.params.get("noexpand") is False else []

    def _pre_remove_target_elt(self):
        self._protect_stacked_aliases()
        super(PFSenseVirtualIPModule, self)._pre_remove_target_elt()

    def _log_fields(self, before=None):
        # Log the operation and address via the base class, without VIP credentials.
        return ""

    def _run_post(self):
        self.runtime_changed = any(self.diff["before"].get(field) != self.diff["after"].get(field) for field in RUNTIME_FIELDS)
        for side in ("before", "after"):
            self.diff[side] = {key: value for key, value in self.diff[side].items() if key != "password"}

    def _update(self):
        before, after = self.diff["before"], self.diff["after"]
        remove = self.mode in BOUND_MODES and before and (
            not after or any(before.get(field) != after.get(field) for field in ("interface", "subnet", "subnet_bits", "vhid"))
        )
        proxy_interfaces = {vip.get("interface") or "wan" for vip in (before, after) if vip} if self.mode == "proxyarp" else set()
        data = {
            "current": after.get("uniqid"),
            "remove": {key: before[key] for key in ("mode", "interface", "subnet")} if remove else None,
            "configure": self.runtime_changed,
            "proxy_interfaces": sorted(proxy_interfaces),
        }
        encoded = b64encode(json.dumps(data).encode()).decode()
        code, _stdout, stderr = self.pfsense.phpshell(APPLY_PHP % encoded, debug=False)
        if code != 0 or stderr:
            self.module.fail_json(msg="VIP configuration was saved, but pfSense could not apply it", changed=True, rc=code)
        return code, "", ""
