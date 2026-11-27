#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = """
---
module: pfsense_gateway
version_added: 0.1.0
author: Frederic Bor (@f-bor)
short_description: Manage pfSense gateways
description:
  - Manage pfSense gateways
notes:
  - The latency and loss thresholds and the probe settings are checked against each other as in the GUI. An option that is not
    set is taken from the gateway, else from the pfSense default. Only the rules that involve an option set by the task are checked.
options:
  name:
    description: Gateway name
    required: true
    type: str
  interface:
    description:
      - Choose which assigned interface this gateway applies to.
      - Required when O(state=present).
    required: false
    type: str
  ipprotocol:
    description: Choose the Internet Protocol this gateway uses.
    required: false
    choices: [ "inet", "inet6" ]
    default: inet
    type: str
  gateway:
    description:
      - Gateway IP address.
      - Required when O(state=present).
    required: false
    type: str
  descr:
    description: The description of the gateway
    required: false
    default: ''
    type: str
  disabled:
    description: Set this option to disable this gateway without removing it from the list.
    default: false
    type: bool
  monitor:
    description: Enter an alternative address here to be used to monitor the link.
    required: false
    type: str
  monitor_disable:
    description: This will consider this gateway as always being up.
    default: false
    type: bool
  action_disable:
    description: No action will be taken on gateway events. The gateway is always considered up.
    default: false
    type: bool
  force_down:
    description: This will force this gateway to be considered down.
    default: false
    type: bool
  weight:
    description: Weight for this gateway when used in a Gateway Group. Must be between 1 and 30.
    default: 1
    type: int
    version_added: 0.7.2
  latencylow:
    description: Low threshold for packet latency in ms.  Default is 200.
    type: int
    version_added: 0.8.0
  latencyhigh:
    description:
      - High threshold for packet latency in ms.  Default is 500.
      - Must be greater than O(latencylow), and less than or equal to O(loss_interval).
    type: int
    version_added: 0.8.0
  losslow:
    description: Low threshold for packet loss in %.  Default is 10.
    type: int
    version_added: 0.7.2
  losshigh:
    description:
      - High threshold for packet loss in %.  Default is 20.
      - Must be greater than O(losslow).
    type: int
  interval:
    description:
      - How often a probe is sent, in ms.  Default is 500.
      - Twice O(interval) plus O(loss_interval) must be less than O(time_period).
    type: int
    version_added: 0.8.0
  loss_interval:
    description:
      - Time without a reply after which a probe is counted as lost, in ms.  Default is 2000.
      - Must be greater than or equal to O(latencyhigh).
    type: int
    version_added: 0.8.0
  time_period:
    description:
      - Time over which the latency and loss are averaged, in ms.  Default is 60000.
      - Must be greater than twice O(interval) plus O(loss_interval).
    type: int
    version_added: 0.8.0
  alert_interval:
    description:
      - Time between two checks for an alarm condition, in ms.  Default is 1000.
      - Must be greater than or equal to O(interval).
    type: int
    version_added: 0.8.0
  data_payload:
    description: Bytes of data sent in each probe.  Default is 1.
    type: int
    version_added: 0.8.0
  nonlocalgateway:
    description:
      - This will allow use of a gateway outside of this interface's subnet.
      - This is usually indicative of a configuration error, but is required for some scenarios.
    default: false
    type: bool
  state:
    description: State in which to leave the gateway
    choices: [ "present", "absent" ]
    default: present
    type: str
"""

EXAMPLES = """
- name: Add gateway
  pfsense_gateway:
    name: default_gw
    interface: wan
    gateway: 1.2.3.4
    state: present

- name: Add gateway with its monitoring settings
  pfsense_gateway:
    name: backup_gw
    interface: opt1
    gateway: 5.6.7.8
    monitor: 8.8.4.4
    latencyhigh: 400
    losshigh: 15
    interval: 1000
    loss_interval: 2000
    time_period: 30000
    alert_interval: 1000
    state: present

- name: Remove gateway
  pfsense_gateway:
    name: vpn_gw
    state: absent
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create gateway 'default_gw', interface='wan', address='1.2.3.4'", "delete gateway 'vpn_gw'"]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.gateway import PFSenseGatewayModule, GATEWAY_ARGUMENT_SPEC, GATEWAY_REQUIRED_IF


def main():
    module = AnsibleModule(argument_spec=GATEWAY_ARGUMENT_SPEC, required_if=GATEWAY_REQUIRED_IF, supports_check_mode=True)

    pfmodule = PFSenseGatewayModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
