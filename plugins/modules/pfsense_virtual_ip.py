#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2021, Jan Wenzel <jan.wenzel@gonicus.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_virtual_ip
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage pfSense virtual ip settings
description:
  - Manage pfSense virtual ip settings
notes:
options:
  mode:
    description: Type
    required: true
    type: str
    choices: ['proxyarp', 'carp', 'ipalias', 'other']
  noexpand:
    description: Disable expansion of this entry into IPs on NAT lists (e.g. 192.168.1.0/24 expands to 256 entries.)
    required: false
    type: bool
  descr:
    description: Description
    required: false
    type: str
  interface:
    description: Interface
    required: true
    type: str
  vhid:
    description: VHID Group
    required: false
    type: int
  advbase:
    description: Advertising Frequency Base
    required: false
    type: int
  advskew:
    description: Advertising Frequency Skew
    required: false
    type: int
  password:
    description: Virtual IP Password
    required: false
    type: str
  uniqid:
    description: Unique ID of Virtual IP in configuration
    required: false
    type: str
  type:
    description: Address Type
    required: false
    type: str
    choices: ['single']
    default: single
  subnet_bits
    description: Network's subnet mask
    required: false
    type: int
    default: 32
  subnet
    description: Network subnet
    required: false
    type: str
  state:
    description: State in which to leave the Virtual IP
    choices: [ "present", "absent" ]
    default: present
    type: str
"""

EXAMPLES = """
"""

RETURN = """
"""

import re
from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


VIRTUALIP_ARGUMENT_SPEC = dict(
    mode=dict(required=True, type='str'),
    interface=dict(required=True, type='str'),
    vhid=dict(required=False, type='int'),
    advskew=dict(required=False, type='int'),
    advbase=dict(required=False, type='int'),
    password=dict(required=False, type='str'),
    uniqid=dict(required=False, type='str'),
    descr=dict(required=False, type='str'),
    type=dict(required=False, type='str', default='single'),
    subnet_bits=dict(required=False, type='int', default=32),
    subnet=dict(required=False, type='str'),
    state=dict(default='present', choices=['present', 'absent'], type='str'),
)

VIRTUALIP_REQUIRED_IF = [
    ["mode", "carp", ["uniqid", "password", "vhid", "advbase"]],
    ["mode", "ipalias", ["uniqid"]],
]

# map field names between ansible and pfsense
params_map = {}

# fields with inverted logic
inverted_list = []

# fields that are not written to pfsense
skip_list = ['state']

class PFSenseVirtualIPModule(PFSenseModuleBase):
    """ module managing pfsense virtual ip settings """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return VIRTUALIP_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseVirtualIPModule, self).__init__(module, pfsense)
        self.name = "virtual_ip"
        self.root_elt = self.pfsense.get_element('virtualip')
        self.obj = dict()

        if self.root_elt is None:
            self.root_elt = self.pfsense.new_element('virtualip')
            self.pfsense.root.append(self.root_elt)

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        def _set_param(target, param):
            if params.get(param) is not None:
                if isinstance(params[param], str):
                    target[param] = params[param]
                else:
                    target[param] = str(params[param])

        def _set_param_bool(target, param):
            if params.get(param) is not None:
                value = params.get(param)
                if value is True and param not in target:
                    target[param] = ''
                elif value is False and param in target:
                    del target[param]

        for param in VIRTUALIP_ARGUMENT_SPEC:
            if param not in skip_list:
                if VIRTUALIP_ARGUMENT_SPEC[param]['type'] == 'bool':
                    _set_param_bool(obj, param)
                else:
                    _set_param(obj, param)

        return obj


    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params
        return

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('vip')

    def _find_target(self):
        """ find the XML target elt """
        for vip_elt in self.root_elt:
            if self.params['mode'] in ['ipalias', 'carp']:
                if vip_elt.find('uniqid') is not None and vip_elt.find('uniqid').text == self.params['uniqid']:
                    return vip_elt
            else:
                if vip_elt.find('descr') is not None and vip_elt.find('descr').text == self.params['descr']:
                    return vip_elt
        return None

    def _remove_deleted_params(self):
        """ Remove from target_elt a few deleted params """
        changed = False
        for param in VIRTUALIP_ARGUMENT_SPEC:
            if VIRTUALIP_ARGUMENT_SPEC[param]['type'] == 'bool':
               if self.pfsense.remove_deleted_param_from_elt(self.target_elt, param, self.obj):
                   changed = True

        return changed

    def _update(self):
        """ make the target pfsense reload """
        cmd = '''
require_once("globals.inc");
require_once("functions.inc");
require_once("filter.inc");
require_once("shaper.inc");
require_once("interfaces.inc");
require_once("util.inc");
$check_carp = false;
$retval = 0;
'''

        if self.params.get('mode') in ['carp', 'ipalias']:
            cmd += '$uniqid = "' + self.params.get('uniqid') +'";\n'
            cmd += '$subnet = "' + self.params.get('subnet') +'";\n'
            cmd += '$interface = "' + self.params.get('interface') +'";\n'
            cmd += '$vipif = get_real_interface($interface);\n'

        if self.params.get('state') == 'present':
            if self.params.get('mode') in ['carp', 'ipalias']:
                cmd += '$check_carp = true;\n'
                cmd += 'foreach ($config["virtualip"]["vip"] as $vip) {\n'
                cmd += 'if ($vip["uniqid"] == $uniqid) {\n'
                cmd += 'interface_' + self.params.get('mode') + '_configure($vip);\n'
                cmd += '}\n}\n'
        else:
            if self.params.get('mode') == 'carp':
                cmd += 'if (does_interface_exist($vipif)) {\n'
                cmd += 'if (is_ipaddrv6($subnet)) {\n'
                cmd += 'mwexec("/sbin/ifconfig " . escapeshellarg($vipif) . " inet6 " . escapeshellarg($subnet) . " delete");\n'
                cmd += '} else {\n'
                cmd += 'pfSense_interface_deladdress($vipif, $subnet);\n'
                cmd += '}\n}\n'
            elif self.params.get('mode') == 'ipalias':
                cmd += 'if (does_interface_exist($vipif)) {\n'
                cmd += 'if (is_ipaddrv6($subnet)) {\n'
                cmd += 'mwexec("/sbin/ifconfig " . escapeshellarg($vipif) . " inet6 " . escapeshellarg($subnet) . " -alias");\n'
                cmd += '} else {\n'
                cmd += 'pfSense_interface_deladdress($vipif, $subnet);\n'
                cmd += '}\n}\n'

        cmd += '''
if ($check_carp === true && !get_carp_status()) {
    set_single_sysctl("net.inet.carp.allow", "1");
}
$retval |= filter_configure();
$retval |= mwexec("/etc/rc.filter_synchronize");
clear_subsystem_dirty('vip');'''

        return self.pfsense.phpshell(cmd)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "vip"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        if before is None:
            for param in VIRTUALIP_ARGUMENT_SPEC:
                if param not in skip_list:
                    if VIRTUALIP_ARGUMENT_SPEC[param]['type'] == 'bool':
                        values += self.format_cli_field(self.obj, param, fvalue=self.fvalue_bool)
                    else:
                        values += self.format_cli_field(self.obj, param)
        else:
            for param in VIRTUALIP_ARGUMENT_SPEC:
                if param not in skip_list:
                    if VIRTUALIP_ARGUMENT_SPEC[param]['type'] == 'bool':
                        values += self.format_updated_cli_field(self.obj, before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
                    else:
                        values += self.format_updated_cli_field(self.obj, before, param, add_comma=(values), log_none=False)

        return values


def main():
    module = AnsibleModule(
        argument_spec=VIRTUALIP_ARGUMENT_SPEC,
        required_if=VIRTUALIP_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseVirtualIPModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
