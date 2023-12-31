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
module: pfsense_default_gateway
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage pfSense default gateways
description:
  - Manage pfSense default gateways for IPv4/IPv6
notes:
options:
  defaultgw4:
    description: Default Gateway (IPv4) (name of existing gateway, auto or none)
    required: false
    type: str
  defaultgw6:
    description: Default Gateway (IPv6) (name of existing gateway, auto or none)
    required: false
    type: str
"""

EXAMPLES = """
pfsensible.core.pfsense_default_gateway:
  defaultgw4: "LANGW"
"""

RETURN = """
"""

from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


DEFAULT_GATEWAY_ARGUMENT_SPEC = dict(
    defaultgw4=dict(required=False, type='str'),
    defaultgw6=dict(required=False, type='str'),
)

# map field names between ansible and pfsense
params_map = {}

# fields with inverted logic
inverted_list = []

# fields that are not written to pfsense
skip_list = ['state']

class PFSenseDefaultGatewayModule(PFSenseModuleBase):
    """ module managing pfsense default gateway settings """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DEFAULT_GATEWAY_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDefaultGatewayModule, self).__init__(module, pfsense)
        self.name = "default_gateway"
        self.root_elt = self.pfsense.get_element('gateways', create_node=True)
        self.obj = dict()

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
                if params[param].lower() == 'auto':
                    target[param] = ''
                elif params[param].lower() == 'none':
                    target[param] = '-'
                else:
                    target[param] = params[param]

        for param in DEFAULT_GATEWAY_ARGUMENT_SPEC:
            _set_param(obj, param)

        return obj


    def _validate_params(self):
        """ do some extra checks on input parameters """
        return

    def run(self, params):
        self.params = params
        self.target_elt = self.root_elt
        self._validate_params()
        self.obj = self._params_to_obj()
        self._add()

    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "default_gateway"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        if before is None:
            for param in DEFAULT_GATEWAY_ARGUMENT_SPEC:
                values += self.format_cli_field(self.obj, param)
        else:
            for param in DEFAULT_GATEWAY_ARGUMENT_SPEC:
                values += self.format_updated_cli_field(self.obj, before, param, add_comma=(values), log_none=False)

        return values


def main():
    module = AnsibleModule(
        argument_spec=DEFAULT_GATEWAY_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseDefaultGatewayModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
