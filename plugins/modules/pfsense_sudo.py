#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2021, Jan Wenzel <jan.wenzel@gonicus.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from pprint import pformat

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_sudo
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage sudo settings
description:
  - Manage pfSense sudo settings
notes:
options:
  config:
    description: Setup each sudo rule
    required: true
    type: list
    elements: dict
    suboptions:
      username:
        description: User or group name (prefix user with user: and group with group:)
        required: True
        type: str
      runas:
        description: Run As
        required: False
        type: str
        default: user:root
      nopasswd:
        description: Require password
        required: False
        type: bool
        default: False
      cmdlist:
        description: List of allowed commands (full paths required)
        required: False
        type: list
        default: ['ALL']
        elements: str
  add_includedir:
    description: Include additional custom configuration files from /usr/local/etc/sudoers.d
    required: False
    type: str
    choices: none, include_start, include_end
"""

EXAMPLES = """
"""

RETURN = """
"""

from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

SUDO_CONFIG_ARGUMENT_SPEC = dict(
    username=dict(required=True, type='str'),
    runas=dict(required=False, type='str', default='user:root'),
    nopasswd=dict(required=False, type='bool', default=False),
    cmdlist=dict(required=False, type='list', elements='str', default=['ALL']),
)

SUDO_ARGUMENT_SPEC = dict(
    row=dict(required=False, type='list', elements='dict', options=SUDO_CONFIG_ARGUMENT_SPEC),
    add_includedir=dict(required=False, type='str', choices=[
        'none',
        'include_start',
        'include_end',
    ], default='none'),
)

class PFSenseSudoModule(PFSenseModuleBase):
    """ module managing pfsense sudo settings """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return SUDO_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseSudoModule, self).__init__(module, pfsense)
        self.name = "sudo"
        pkgs_elt = self.pfsense.get_element('installedpackages')
        sudo_elt = self.pfsense.get_element('sudo', pkgs_elt, create_node=True)
        self.root_elt = self.pfsense.get_element('config', sudo_elt, create_node=True)
        self.target_elt = self.root_elt
        self.params = dict()
        self.obj = dict()
        self.before = None
        self.before_elt = None
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

        def _set_param_list(target, param):
            if params.get(param) is not None:
                if param == 'row':
                    rows = []
                    for entry in params.get(param):
                        row = dict()
                        for subparam in SUDO_CONFIG_ARGUMENT_SPEC:
                            if entry.get(subparam) is not None:
                                value = entry.get(subparam)
                                if SUDO_CONFIG_ARGUMENT_SPEC[subparam]['type'] == 'bool':
                                    if value is True:
                                        row[subparam] = 'ON'
                                elif SUDO_CONFIG_ARGUMENT_SPEC[subparam]['type'] == 'list':
                                    if subparam == 'cmdlist':
                                        row[subparam] = ','.join(value)
                                else:
                                    if isinstance(value, str):
                                        row[subparam] = value
                                    else:
                                        row[subparam] = str(value)
                        rows.append(row)

                    target[param] = rows

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

        for param in SUDO_ARGUMENT_SPEC:
            if SUDO_ARGUMENT_SPEC[param]['type'] == 'list':
                _set_param_list(obj, param)
            elif SUDO_ARGUMENT_SPEC[param]['type'] == 'bool':
                _set_param_bool(obj, param)
            else:
                _set_param(obj, param)

        # self.module.fail_json(isinstance(obj['row'], list))

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
        for param in SUDO_ARGUMENT_SPEC:
            if SUDO_ARGUMENT_SPEC[param]['type'] == 'bool':
                if self.pfsense.remove_deleted_param_from_elt(self.target_elt, param, self.obj):
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
        cmd = '''
require_once("sudo.inc");
$retval = 0;
$retval |= sudo_write_config();
'''
        return self.pfsense.phpshell(cmd)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "sudo"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        for param in SUDO_ARGUMENT_SPEC:
            if SUDO_ARGUMENT_SPEC[param]['type'] == 'bool':
                values += self.format_updated_cli_field(self.obj, self.before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
            elif SUDO_ARGUMENT_SPEC[param]['type'] == 'list':
                pass
            else:
                values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

        return values


def main():
    module = AnsibleModule(
        argument_spec=SUDO_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseSudoModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
