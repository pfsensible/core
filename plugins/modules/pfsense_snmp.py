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
module: pfsense_snmp
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage pfSense snmp settings
description:
    - Manage pfSense snmp settings
notes:
options:
    enable:
        description: Enable SNMP Service
        required: false
        type: bool
    pollport:
        description: SNMP Service Port
        required: false
        type: int
        default: 161
    syslocation:
        description: System Location
        required: false
        type: str
    syscontact:
        description: System Contact
        required: false
        type: str
    rocommunity:
        description: Read Community String
        required: false
        type: str
        default: public
    trapenable:
        description: Enable SNMP Trap
        required: false
        type: bool
    trapserver:
        description: SNMP Trap Target Server
        required: false
        type: str
    trapserverport:
        description: SNMP Trap Target Port
        required: false
        type: int
    trapstring:
        description: SNMP Trap String
        required: false
        type: str
    mibii:
        description: Enable SNMP MibII Module
        required: false
        type: bool
    netgraph:
        description: Enable SNMP Netgraph Module
        required: false
        type: bool
    pf:
        description: Enable SNMP PF Module
        required: false
        type: bool
    hostres:
        description: Enable SNMP Host Resources Module
        required: false
        type: bool
    ucd:
        description: Enable SNMP UCD Module
        required: false
        type: bool
    regex:
        description: Enable SNMP Regex Module
        required: false
        type: bool
    bindip:
        description: Bind Interfaces
        required: false
        type: list
        elements: str
"""

EXAMPLES = """
pfsensible.core.pfsense_snmp:
    enable: true
    syslocation: "Some Datacenter"
    bindip:
        - "lan"
        - "lo0"
"""

RETURN = """
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: [
        "update snmp snmp set enable=True, syslocation='Some Datacenter', bindip='lan,lo0'"
    ]
"""

import re
from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

SNMP_ARGUMENT_SPEC = dict(
    enable=dict(required=False, type='bool'),
    pollport=dict(required=False, type='int'),
    syslocation=dict(required=False, type='str'),
    syscontact=dict(required=False, type='str'),
    rocommunity=dict(required=False, type='str', default='public'),
    trapenable=dict(required=False, type='bool'),
    trapserver=dict(required=False, type='str'),
    trapserverport=dict(required=False, type='int', default=162),
    trapstring=dict(required=False, type='str'),
    mibii=dict(required=False, type='bool', default=True),
    netgraph=dict(required=False, type='bool', default=True),
    pf=dict(required=False, type='bool', default=True),
    hostres=dict(required=False, type='bool', default=True),
    ucd=dict(required=False, type='bool', default=True),
    regex=dict(required=False, type='bool', default=True),
    bindip=dict(required=False, type='list', elements='str', default=['all']),
)

modules = ['mibii', 'netgraph', 'pf', 'hostres', 'ucd', 'regex']


class PFSenseSnmpModule(PFSenseModuleBase):
    """ module managing pfsense snmp settings """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return SNMP_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseSnmpModule, self).__init__(module, pfsense)
        self.name = "snmp"
        self.root_elt = self.pfsense.get_element('snmpd')
        self.target_elt = self.root_elt
        self.params = dict()
        self.obj = dict()
        self.before = None
        self.before_elt = None
        self.route_cmds = list()
        self.params_to_delete = list()

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = self.pfsense.element_to_dict(self.root_elt)
        self.before = deepcopy(obj)
        self.before_elt = deepcopy(self.root_elt)
        modules = obj['modules']

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

        def _set_param_list(target, param):
            if params.get(param) is not None:
                target[param] = ','.join(params[param])

        _set_param_bool(obj, 'enable')
        _set_param(obj, 'pollport')
        _set_param(obj, 'syslocation')
        _set_param(obj, 'syscontact')
        _set_param(obj, 'rocommunity')
        _set_param_bool(obj, 'trapenable')
        _set_param(obj, 'trapserver')
        _set_param(obj, 'trapserverport')
        _set_param(obj, 'trapstring')
        _set_param_bool(modules, 'mibii')
        _set_param_bool(modules, 'netgraph')
        _set_param_bool(modules, 'pf')
        _set_param_bool(modules, 'hostres')
        _set_param_bool(modules, 'ucd')
        _set_param_bool(modules, 'regex')
        _set_param_list(obj, 'bindip')

        return obj


    def _validate_params(self):
        """ do some extra checks on input parameters """
        pass

    ##############################
    # XML processing
    #
    def _remove_deleted_params(self):
        """ Remove from target_elt a few deleted params """
        changed = False
        for param in SNMP_ARGUMENT_SPEC:
            if SNMP_ARGUMENT_SPEC[param]['type'] == 'bool':
                if param in modules:
                    continue
                if self.pfsense.remove_deleted_param_from_elt(self.target_elt, param, self.obj):
                    changed = True

        modules_elt = self.target_elt.find('modules')
        _modules = self.obj['modules']
        for param in modules:
            if self.pfsense.remove_deleted_param_from_elt(modules_elt, param, _modules):
                changed = True

        return changed

    ##############################
    # run
    #
    def run(self, params):
        """ process input params to add/update/delete """
        self.params = params
        self.target_elt = self.root_elt
        self._validate_params()
        self.obj = self._params_to_obj()
        self._add()

    def _update(self):
        """ make the target pfsense reload """
        for cmd in self.route_cmds:
            self.module.run_command(cmd)

        cmd = '''
require_once("functions.inc");
$retval = 0;
$retval |= services_snmpd_configure();'''

        return self.pfsense.phpshell(cmd)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "snmp"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        for param in SNMP_ARGUMENT_SPEC:
            if param in modules:
                continue
            if SNMP_ARGUMENT_SPEC[param]['type'] == 'bool':
                values += self.format_updated_cli_field(self.obj, self.before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
            else:
                values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

        for param in modules:
            values += self.format_updated_cli_field(self.obj['modules'], self.before['modules'], param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)

        return values


def main():
    module = AnsibleModule(
        argument_spec=SNMP_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseSnmpModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
