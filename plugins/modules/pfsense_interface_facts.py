#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_interface_facts
version_added: 0.5.2
author: Jan Wenzel (@coffeelover)
short_description: Gather pfsense interfaces
description:
  - Gather pfSense interfaces.
options:
notes:
"""

EXAMPLES = """
- name: Gather interface facts
  pfsense_interface_facts:
"""

RETURN = """
ansible_facts:
  description: Facts to add to ansible_facts.
  returned: always
  type: complex
  contains:
    interface_facts:
      description:
        - Maps the interfaces to a list of dicts with additional interface information
      returned: always
      type: dict
      contains:
        dmesg:
          description: The interface information from dmesg
          returned: always
          type: str
        friendly:
          description: The interface friendly name used in the config
          returned: always
          type: str
        interface_name:
          description: The interface name
          returned: always
          type: str
        ipaddr:
          description: The ipv4 address
          returned: always
          type: str
        macaddr:
          description: The MAC address
          returned: always
          type: str
        up:
          description: The up status
          returned: always
          type: bool
      sample: |-
      {
        "interface_facts": [
            {
                "dmesg": "Intel(R) PRO/1000 Network Connection",
                "friendly": "wan",
                "interface_name": "em0",
                "ipaddr": "192.168.178.190",
                "mac": "08:00:27:86:e7:0f",
                "up": true
            },
            {
                "dmesg": "Intel(R) PRO/1000 Network Connection",
                "friendly": "lan",
                "interface_name": "em1",
                "ipaddr": "192.168.61.10",
                "mac": "08:00:27:a1:4c:70",
                "up": true
            }
        ],
      }
"""

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase
from ansible_collections.pfsensible.core.plugins.module_utils.interface import PFSenseInterfaceModule
from ansible.module_utils.basic import AnsibleModule

INTERFACE_FACTS_ARGUMENT_SPEC = dict()
INTERFACE_FACTS_REQUIRED_IF = []
INTERFACE_FACTS_MUTUALLY_EXCLUSIVE = []


class PFSenseInterfaceFactsModule(PFSenseModuleBase):
    """ module managing pfsense interfaces """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return INTERFACE_FACTS_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseInterfaceFactsModule, self).__init__(module, pfsense)
        self.name = "pfsense_interface_facts"
        self.apply = False
        self.obj = dict()
        self.root_elt = self.pfsense.interfaces
        self.interface_module = PFSenseInterfaceModule(module)

    def run(self, params):
        """ process input params to add/update/delete """
        from pprint import pformat
        interfaces = self.interface_module._get_interface_list()
        results = {'ansible_facts': {
            'interface_facts': []
        }}
        for interface in interfaces:
            interface_facts = {'interface_name': interface}
            interface_facts.update(interfaces[interface])
            if 'friendly' not in interface_facts:
              interface_facts['friendly'] = None
            results['ansible_facts']['interface_facts'].append(interface_facts)
        self.module.exit_json(**results)


def main():
    module = AnsibleModule(
        argument_spec=INTERFACE_FACTS_ARGUMENT_SPEC,
        required_if=INTERFACE_FACTS_REQUIRED_IF,
        mutually_exclusive=INTERFACE_FACTS_MUTUALLY_EXCLUSIVE,
        supports_check_mode=True)

    pfmodule = PFSenseInterfaceFactsModule(module)
    pfmodule.run(module.params)


if __name__ == '__main__':
    main()
