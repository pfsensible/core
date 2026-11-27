# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from base64 import b64encode
import json

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

VLAN_ARGUMENT_SPEC = dict(
    state=dict(default="present", choices=["present", "absent"]),
    interface=dict(required=True, type="str"),
    vlan_id=dict(required=True, type="int"),
    priority=dict(default=None, required=False, type="int"),
    descr=dict(default="", type="str"),
)


# Follow the runtime operations in interfaces_vlan_edit.php and interfaces_vlan.php.
APPLY_PHP = r"""
require_once("interfaces.inc");
foreach (json_decode(base64_decode("%s"), true) as $change) {
    if (isset($change["remove"])) {
        $vlanif = $change["remove"];
        if (does_interface_exist($vlanif, true)) {
            pfSense_interface_destroy($vlanif);
        }
        if (does_interface_exist($vlanif, true)) {
            fwrite(STDERR, "Could not remove VLAN interface {$vlanif}\n");
            exit(1);
        }
    } else {
        $vlan = $change["configure"];
        $vlanif = interface_vlan_configure($vlan);
        if ($vlanif !== $vlan["vlanif"] || !does_interface_exist($vlanif)) {
            pfSense_interface_destroy($vlan["vlanif"]);
            fwrite(STDERR, "Could not configure VLAN interface {$vlan['vlanif']}\n");
            exit(1);
        }
    }
}
"""


class PFSenseVlanModule(PFSenseModuleBase):
    """module managing pfsense vlans"""

    @staticmethod
    def get_argument_spec():
        """return argument spec"""
        return VLAN_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseVlanModule, self).__init__(
            module,
            pfsense,
            root="vlans",
            create_root=True,
            node="vlan",
            key="vlanif",
            arg_route=dict(interface=dict(parse=PFSenseVlanModule._parse_parent)),
            map_param=[("interface", "if"), ("vlan_id", "tag"), ("priority", "pcp")],
            create_default=dict(tag_type="ctag"),
        )
        self.argument_spec = VLAN_ARGUMENT_SPEC  # Also used with pfsense_aggregate.
        self.vlan_changes = []

        # get physical interfaces on which vlans can be set
        get_interface_cmd = (
            'require_once("/etc/inc/interfaces.inc");'
            "$portlist = get_interface_list();"
            "$lagglist = get_lagg_interface_list();"
            "$portlist = array_merge($portlist, $lagglist);"
            "foreach ($lagglist as $laggif => $lagg) {"
            "    $laggmembers = explode(',', $lagg['members']);"
            "    foreach ($laggmembers as $lagm)"
            "        if (isset($portlist[$lagm]))"
            "            unset($portlist[$lagm]);"
            "}"
        )

        if self.pfsense.is_at_least_2_5_0():
            get_interface_cmd += (
                "$list = array();"
                "foreach ($portlist as $ifn => $ifinfo) {"
                '  $list[$ifn] = $ifn . " (" . $ifinfo["mac"] . ")";'
                "  $iface = convert_real_interface_to_friendly_interface_name($ifn);"
                "  if (isset($iface) && strlen($iface) > 0)"
                '    $list[$ifn] .= " - $iface";'
                "}"
                "echo json_encode($list);"
            )
        else:
            get_interface_cmd += (
                "$list = array();foreach ($portlist as $ifn => $ifinfo)   if (is_jumbo_capable($ifn))       array_push($list, $ifn);echo json_encode($list);"
            )

        self.interfaces = self.pfsense.php(get_interface_cmd)

    ##############################
    # params processing
    #
    def _parent_port(self, name):
        """Resolve a physical port or one of its assignments."""
        if name in self.interfaces:
            return name
        port = self.pfsense.get_interface_port_by_display_name(name)
        if port is None:
            port = self.pfsense.get_interface_port(name)
        if port is None or port not in self.interfaces:
            self.module.fail_json(msg=f"Vlans can't be set on interface {name}")
        return port

    def _parse_parent(self, name, params, obj):
        obj[name] = self._parent_port(params[name])

    def _params_to_obj(self):
        """Retain the parent and tag as the identity for both states."""
        if self.params.get("state") == "absent":
            return {"if": self._parent_port(self.params["interface"]), "tag": str(self.params["vlan_id"])}

        obj = super(PFSenseVlanModule, self)._params_to_obj()
        obj.setdefault("pcp", "")
        obj["vlanif"] = "{if}.{tag}".format(**obj)
        return obj

    def _validate_params(self):
        """Check VLAN tag and priority ranges."""
        params = self.params

        # check vlan
        if params["vlan_id"] < 1 or params["vlan_id"] > 4094:
            self.module.fail_json(msg="vlan_id must be between 1 and 4094 on interface {0}".format(params["interface"]))

        # check priority
        if params.get("priority") is not None and (params["priority"] < 0 or params["priority"] > 7):
            self.module.fail_json(msg="priority must be between 0 and 7 on interface {0}".format(params["interface"]))

    ##############################
    # XML processing
    #
    def _queue_configure(self):
        vlan = self.pfsense.element_to_dict(self.target_elt)
        vlan.setdefault("tag_type", "ctag")
        self.vlan_changes.append({"configure": vlan})

    def _copy_and_add_target(self):
        super(PFSenseVlanModule, self)._copy_and_add_target()
        self._queue_configure()

    def _copy_and_update_target(self):
        # Preserve names already in use by interface assignments.
        self.obj["vlanif"] = self.target_elt.findtext("vlanif") or self.obj["vlanif"]
        before, changed = super(PFSenseVlanModule, self)._copy_and_update_target()
        if changed:
            self._queue_configure()
        return before, changed

    def _find_target(self):
        """Find the VLAN by its parent port and tag."""
        return self.pfsense.find_vlan(self.obj["if"], self.obj["tag"])

    def _pre_remove_target_elt(self):
        super(PFSenseVlanModule, self)._pre_remove_target_elt()
        vlanif = self.target_elt.findtext("vlanif") or "{if}.{tag}".format(**self.obj)
        if self.pfsense.get_interface_by_port(vlanif) is not None:
            self.module.fail_json(msg="vlan {tag} on {if} cannot be deleted because it is still being used as an interface".format(**self.obj))
        self.vlan_changes.append({"remove": vlanif})

    def get_update_cmds(self):
        """Build the PHP for both standalone and aggregate updates."""
        encoded = b64encode(json.dumps(self.vlan_changes).encode()).decode()
        return APPLY_PHP % encoded

    def _update(self):
        rc, stdout, stderr = self.pfsense.phpshell(self.get_update_cmds(), debug=False)
        if rc != 0:
            self.module.fail_json(msg="VLAN configuration was saved, but pfSense could not apply it", changed=True, rc=rc, stderr=stderr)
        return rc, stdout, stderr

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """return obj's name"""
        return "'{0}.{1}'".format(self.obj["if"], self.obj["tag"])

    def _log_fields(self, before=None):
        """generate pseudo-CLI command fields parameters to create an obj"""
        values = ""
        if before is None:
            values += self.format_cli_field(self.obj, "descr")
            values += self.format_cli_field(self.obj, "pcp", fname="priority")
        else:
            values += self.format_updated_cli_field(self.obj, before, "pcp", add_comma=(values), fname="priority")
            values += self.format_updated_cli_field(self.obj, before, "descr", add_comma=(values))
        return values
