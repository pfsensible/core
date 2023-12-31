#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018-2020, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_widgets
version_added: 0.1.0
short_description: Manage pfSense dashboard widgets
description:
  >
    Manage pfSense widgets
author: Orion Poplawski (@opoplawski)
notes:
options:
  sequence:
    description: The ordered list of the widgets
    required: true
    type: list
    elements: dict
  period:
    description: 
    elements: str
"""

EXAMPLES = """
- name: Configure dashboard widgets
  pfsense_widgets:
    sequence:
      - name: "system_information"
        column: "col1"
        state: "open"
      - name: "interfaces"
        column: "col2"
        state: "open"
      - name: "carp_status"
        column: "col2"
        state: "open"
"""

RETURN = """

"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


class PFSenseWidgetsModule(PFSenseModuleBase):
    """ module managing pfsense dashboard widgets """

    def __init__(self, module, pfsense=None):
        super(PFSenseWidgetsModule, self).__init__(module, pfsense)
        self.name = "pfsense_widgets"
        self.root_elt = self.pfsense.get_element('widgets')

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('widgets')

    def _find_target(self):
        return self.pfsense.find_elt('widgets')

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return self.obj['name']

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        return values


def main():
    module = AnsibleModule(
        argument_spec={
            'name': {
              'required': True,
              'type': 'str',
              'choices': [

              ],
            },
            'column': {
              'required': True,
              'type': 'int',
              'choices': [
                1,
                2,
                3,
                4,
                5,
                6,
              ],
            },
            'open': {
              'required': False,
              'type': 'bool',
              'default': True,
            },
        },
        supports_check_mode=True)

    pfmodule = PFSenseWidgetsModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
