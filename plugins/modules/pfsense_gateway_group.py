#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_gateway_group

short_description: Manage pfSense gateway groups

version_added: "0.7.2"

description:
  - Manage pfSense gateway groups.

options:
  name:
    description: The name of the gateway group.
    required: true
    type: str
  state:
    description: State in which to leave the gateway group.
    default: present
    choices: ['present', 'absent']
    type: str
  keep_failover_states:
    description: Keep Failover States of the gateway group. Defaults to unset.
    choices: ['', 'keep', 'kill']
    type: str
  trigger:
    description: Trigger Level of the gateway group. When to trigger exclusion of a member. Defaults to down.
    default: down
    choices: ['down', 'downloss', 'downlatency', 'downlosslatency']
    type: str
  descr:
    description: Description of the gateway group. Used to identify the gateway group.
    type: str
  members:
    description: The members of the gateway group.
    type: list
    elements: dict
    suboptions:
      gateway:
        type: str
        required: true
        description: The name of the gateway.
      tier:
        type: int
        required: true
        description: The tier of the gateway. This should be a number between 1 and the number of members.
      virtualip:
        type: str
        required: true
        description: The virtual IP of the gateway.  This should either be `address` or the name of a virtual IP.


author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Add WANGW_FAILOVER gateway group
  pfsensible.core.pfsense_gateway group:
    name: WANGW_FAILOVER
    keep_failover_states: keep
    trigger: downlosslatency
    descr: Item full
    members:
      - gateway: WANGW
        tier: 1
        virtualip: address
      - gateway: WAN1GW
        tier: 2
        virtualip: WAN1 CARP
    state: present

- name: Remove WANGW_FAILOVER gateway group
  pfsensible.core.pfsense_gateway group:
    name: WANGW_FAILOVER
    state: absent
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: ["create gateway_group 'WANGW_FAILOVER'", "update gateway_group 'WANGW_FAILOVER' set ...", "delete gateway_group 'WANGW_FAILOVER'"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

GATEWAY_GROUP_ARGUMENT_SPEC = dict(
    # Only name should be required here - othewise you cannot remove an item with just 'name'
    # Required arguments for creation should be noted in GATEWAY_GROUP_REQUIRED_IF = ['state', 'present', ...] below
    name=dict(required=True, type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    keep_failover_states=dict(type='str', choices=['', 'keep', 'kill']),
    trigger=dict(type='str', choices=['down', 'downloss', 'downlatency', 'downlosslatency'], default='down'),
    descr=dict(type='str'),
    members=dict(type='list', elements='dict'),
)

GATEWAY_GROUP_REQUIRED_IF = [
    ['state', 'present', ['members']],
]


def p2o_members(self, name, params, obj):
    """ parse the list of members into format required for the XML element """
    obj['item'] = []
    for member in params[name]:
        if member["virtualip"] != "address":
            if (vip := self.pfsense.get_virtual_ip_interface(member["virtualip"])) is None:
                self.module.fail_json(msg=f"Cannot find virtual IP '{member['virtualip']}'")
        else:
            vip = 'address'
        obj['item'].append(f"{member['gateway']}|{member['tier']}|{vip}")


GATEWAY_GROUP_ARG_ROUTE = dict(
    members=dict(parse=p2o_members),
)

GATEWAY_GROUP_CREATE_DEFAULT = dict(
    trigger='down',
)


class PFSenseGatewayGroupModule(PFSenseModuleBase):
    """ module managing pfsense gateway groups """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return GATEWAY_GROUP_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseGatewayGroupModule, self).__init__(module, pfsense, root='gateways', node='gateway_group', key='name',
                                                        arg_route=GATEWAY_GROUP_ARG_ROUTE, create_default=GATEWAY_GROUP_CREATE_DEFAULT)


def main():
    module = AnsibleModule(
        argument_spec=GATEWAY_GROUP_ARGUMENT_SPEC,
        required_if=GATEWAY_GROUP_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseGatewayGroupModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
