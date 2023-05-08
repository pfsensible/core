#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_nat_outbound_mode
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage pfSense Outbound NAT Mode
description:
  - Manage pfSense Outbound NAT Mode
notes:
options:
  mode:
    description: The outbound nat mode
    required: true
    default: null
    type: str
    choices: ['automatic', 'hybrid', 'advanced', 'disabled']
"""

EXAMPLES = """
- name: "Set NAT outbound mode to hybrid"
  pfsense_nat_outbound_mode:
    mode: 'hybrid'
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["update nat_outbound_mode"]
"""

from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

NAT_OUTBOUND_MODE_ARGUMENT_SPEC = dict(
    mode=dict(type='str', required=True, choices=['automatic', 'hybrid', 'advanced', 'disabled'])
)


class PFSenseNatOutboundModeModule(PFSenseModuleBase):
    """ module managing pfsense outbound nat mode """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return NAT_OUTBOUND_MODE_ARGUMENT_SPEC

    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "mode"

    def __init__(self, module, pfsense=None):
        super(PFSenseNatOutboundModeModule, self).__init__(module, pfsense)
        self.name = "nat_outbound"
        self.obj = dict()
        self.before = None
        self.before_elt = None
        nat_elt = self.pfsense.get_element('nat', create_node=True)
        self.root_elt = self.pfsense.get_element('outbound', nat_elt, create_node=True)

    def _params_to_obj(self):
        """ return a dict from module params """

        params = self.params

        obj = self.pfsense.element_to_dict(self.root_elt)
        self.before = deepcopy(obj)
        self.before_elt = deepcopy(self.root_elt)

        obj = dict()
        obj['mode'] = params['mode']
        return obj

    def run(self, params):
        self.params = params
        self.target_elt = self.root_elt
        self.obj = self._params_to_obj()
        self._add()

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        return self.format_updated_cli_field(self.obj, self.before, 'mode')

    def _update(self):
        return self.pfsense.phpshell('''require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('natconf'); clear_subsystem_dirty('filter'); }''')

def main():
    module = AnsibleModule(
        argument_spec=NAT_OUTBOUND_MODE_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseNatOutboundModeModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
