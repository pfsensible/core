# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Example
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

LAGG_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    laggif=dict(required=True, type='str'),  # z.B. "lagg0", "lagg1" usw.
    members=dict(required=True, type='list', elements='str'),
    proto=dict(default='lacp', choices=['lacp', 'failover', 'loadbalance', 'roundrobin', 'none']),
    lacptimeout=dict(default='fast', choices=['fast', 'slow']),
    lagghash=dict(default='l2,l3,l4', type='str'),
    descr=dict(default='', type='str'),
)


class PFSenseLaggModule(PFSenseModuleBase):
    @staticmethod
    def get_argument_spec():
        return LAGG_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseLaggModule, self).__init__(module, pfsense)
        self.name = "pfsense_lagg"
        self.root_elt = self.pfsense.get_element('laggs')
        self.obj = dict()
        if self.root_elt is None:
            self.root_elt = self.pfsense.new_element('laggs')
            self.pfsense.root.append(self.root_elt)

        self.setup_lagg_cmds = ""

    def _params_to_obj(self):
        params = self.params
        obj = dict()

        obj['laggif'] = params['laggif']
        obj['members'] = ",".join(params['members'])
        obj['proto'] = params['proto']
        obj['lacptimeout'] = params['lacptimeout']
        obj['lagghash'] = params['lagghash']
        obj['descr'] = params['descr']

        return obj

    def _validate_params(self):
        if not self.params['members']:
            self.module.fail_json(msg="members muss mindestens ein Interface enthalten.")

    def _find_target(self):
        requested = self.obj['laggif']
        for lagg_node in self.root_elt.findall('lagg'):
            node_laggif = lagg_node.findtext('laggif') or ''
            if node_laggif.lower() == requested.lower():
                self.obj['laggif'] = node_laggif
                return lagg_node
        return None

    def _create_target(self):
        return self.pfsense.new_element('lagg')

    def _copy_and_add_target(self):
        super(PFSenseLaggModule, self)._copy_and_add_target()
        self.setup_lagg_cmds += self._cmd_create()

    def _copy_and_update_target(self):
        before_laggif = self.target_elt.find('laggif').text
        (before, changed) = super(PFSenseLaggModule, self)._copy_and_update_target()
        if changed:
            self.setup_lagg_cmds += "pfSense_interface_destroy('{}');\n".format(before_laggif)
            self.setup_lagg_cmds += self._cmd_create()
        return (before, changed)

    def _pre_remove_target_elt(self):
        if self.pfsense.get_interface_by_port(self.obj['laggif']) is not None:
            self.module.fail_json(
                msg="LAGG {} is in use therefore you can't delete it.".format(self.obj['laggif'])
            )
        self.setup_lagg_cmds += "pfSense_interface_destroy('{}');\n".format(self.obj['laggif'])

    def _cmd_create(self):
        cmd = "$lagg = array();\n"
        cmd += "$lagg['laggif'] = '{}';\n".format(self.obj['laggif'])
        cmd += "$lagg['members'] = '{}';\n".format(self.obj['members'])
        cmd += "$lagg['descr'] = '{}';\n".format(self.obj['descr'])
        cmd += "$lagg['proto'] = '{}';\n".format(self.obj['proto'])
        cmd += "$lagg['lacptimeout'] = '{}';\n".format(self.obj['lacptimeout'])
        cmd += "$lagg['lagghash'] = '{}';\n".format(self.obj['lagghash'])
        cmd += "$laggif = interface_lagg_configure($lagg);\n"
        cmd += "if (($laggif == NULL) || ($laggif != $lagg['laggif'])) {\n"
        cmd += "    pfSense_interface_destroy('{}');\n".format(self.obj['laggif'])
        cmd += "} else {\n"
        interface = self.pfsense.get_interface_by_port(self.obj['laggif'])
        if interface is not None:
            cmd += "    interface_configure('{}', true);\n".format(interface)
        cmd += "}\n"
        return cmd

    def get_update_cmds(self):
        cmd = 'require_once("filter.inc");\n'
        if self.setup_lagg_cmds:
            cmd += 'require_once("interfaces.inc");\n'
            cmd += self.setup_lagg_cmds
        cmd += "if (filter_configure() == 0) { clear_subsystem_dirty('filter'); }\n"
        return cmd

    def _update(self):
        return self.pfsense.phpshell(self.get_update_cmds())

    def _get_obj_name(self):
        return "'{}'".format(self.obj['laggif'])

    def _log_fields(self, before=None):
        vals = ''
        if before is None:
            # Neu
            vals += self.format_cli_field(self.obj, 'proto')
            vals += self.format_cli_field(self.obj, 'members')
            vals += self.format_cli_field(self.obj, 'descr')
        else:
            vals += self.format_updated_cli_field(self.obj, before, 'proto', add_comma=(vals))
            vals += self.format_updated_cli_field(self.obj, before, 'members', add_comma=(vals))
            vals += self.format_updated_cli_field(self.obj, before, 'descr', add_comma=(vals))
        return vals