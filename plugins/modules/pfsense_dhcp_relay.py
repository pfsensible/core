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
module: pfsense_dhcp_relay
version_added: "0.4.7"
author: Jan Wenzel (@coffeelover)
short_description: Manage pfSense dhcp relay settings
description:
  - Manage pfSense dhcp relay settings
notes:
options:
  enable:
    description: Enable DHCP Relay
    required: false
    type: bool
  interface:
    description: comma separated list of listening interfaces
    required: false
    type: str
  agentoption:
    description: Append circuit ID and agent ID to requests
    required: false
    type: bool
  server:
    description: comma separated list of destination servers
    required: false
    type: str
"""

EXAMPLES = """
- name: setup dhcp relay
  pfsense_dhcp_relay:
    enable: true
    server: dhcp1.example.com,dhcp2.example.com
    agentoption: true
    interface: wan,lan
"""

RETURN = """
"""

import re
from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

DHCP_RELAY_ARGUMENT_SPEC = dict(
    enable=dict(required=False, type='bool'),
    interface=dict(required=False, type='str'),
    server=dict(required=False, type='str'),
    agentoption=dict(required=False, type='bool'),
)

# rename the reserved words with log prefix
params_map = {
}

# fields with inverted logic
inverted_list = []


class PFSenseDHCPRelayModule(PFSenseModuleBase):
    """ module managing pfsense dhcp_relay settings """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return LOG_SETTINGS_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDHCPRelayModule, self).__init__(module, pfsense)
        self.name = "dhcp_relay"
        self.root_elt = self.pfsense.get_element('dhcrelay')
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

        def _set_param(target, param):
            # get possibly mapped settings name
            _param = params_map.get(param, param)
            if params.get(param) is not None:
                if param == 'sourceip':
                    target[param] = self._get_source_ip_interface(params[param])
                else:
                    if isinstance(params[param], str):
                        target[_param] = params[param]
                    else:
                        target[_param] = str(params[param])

        def _set_param_bool(target, param):
            # get possibly mapped settings name
            _param = params_map.get(param, param)
            if params.get(param) is not None:
                value = not params.get(param) if param in inverted_list else params.get(param)
                if value is True and _param not in target:
                    target[_param] = ''
                elif value is False and _param in target:
                    del target[_param]

        for param in DHCP_RELAY_ARGUMENT_SPEC:
            if DHCP_RELAY_ARGUMENT_SPEC[param]['type'] == 'bool':
                _set_param_bool(obj, param)
            else:
                _set_param(obj, param)

        return obj


    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params


    ##############################
    # XML processing
    #
    def _remove_deleted_params(self):
        """ Remove from target_elt a few deleted params """
        changed = False
        for param in DHCP_RELAY_ARGUMENT_SPEC:
            if DHCP_RELAY_ARGUMENT_SPEC[param]['type'] == 'bool':
                _param = params_map.get(param, param)
                if self.pfsense.remove_deleted_param_from_elt(self.target_elt, _param, self.obj):
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
require_once("filter.inc");
$retval = 0;
$retval |= services_dhcrelay_configure();
$retval |= filter_configure();'''

        return self.pfsense.phpshell(cmd)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "dhcrelay"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        for param in DHCP_RELAY_ARGUMENT_SPEC:
            _param = params_map.get(param, param)
            if DHCP_RELAY_ARGUMENT_SPEC[param]['type'] == 'bool':
                values += self.format_updated_cli_field(self.obj, self.before, _param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
            else:
                values += self.format_updated_cli_field(self.obj, self.before, _param, add_comma=(values), log_none=False)

        return values


def main():
    module = AnsibleModule(
        argument_spec=DHCP_RELAY_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseDHCPRelayModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
