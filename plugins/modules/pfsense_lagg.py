#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Example
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_lagg
version_added: "0.1.0"
author:
  - "Your Name (@your_github_handle)"
short_description: Manage pfSense LAGG (Link Aggregations)
description:
  - This module manages pfSense LAGG interfaces (Link Aggregation). It can create, update, or remove LAGGs.
options:
  laggif:
    description:
      - The name of the LAGG interface (e.g. C(lagg0), C(lagg1), etc.).
      - Make sure this matches what pfSense actually stores in its config (case sensitivity may matter unless you
        implement case-insensitive matching in your code).
    required: true
    type: str
  members:
    description:
      - A list of physical interfaces to be aggregated, e.g. C(['igb0','igb1']).
      - They must exist on the pfSense device and should not be part of any other LAGG.
    required: true
    type: list
    elements: str
  proto:
    description:
      - The LAGG protocol to use. Available protocols:
        - C(none): Disables any traffic on this LAGG without disabling the interface itself.
        - C(lacp): Uses the IEEE 802.3ad Link Aggregation Control Protocol (LACP) and the Marker Protocol.
          Negotiates aggregable links with the peer into one or more Link Aggregated Groups.
        - C(failover): Sends and receives traffic through the master port only. If the master port
          becomes unavailable, the next active port is used.
        - C(loadbalance): Balances outgoing traffic across active ports based on hashed protocol header
          information, and accepts incoming traffic from any active port. (Static setup, no dynamic negotiation.)
        - C(roundrobin): Distributes outgoing traffic in a round-robin fashion through all active ports,
          and accepts incoming traffic from any active port.
    choices: ["none", "lacp", "failover", "loadbalance", "roundrobin"]
    default: "lacp"
    type: str
  lacptimeout:
    description:
      - LACP timeout mode (only relevant if proto = lacp).
      - C(fast) or C(slow). Typically defaults to fast on pfSense.
    choices: ["fast", "slow"]
    default: "fast"
    type: str
  lagghash:
    description:
      - Hash method for load distribution.
      - Possible options are:
        - (l2,l3,l4) layer 2/3/4 (default)
        - (l2) layer 2 (MAC addresses)
        - (l3) layer 3 (IP addresses)
        - (l4) layer 4 (Port numbers)
        - (l2,l3) layer 2/3 (MAC + IP)
        - (l3,l4) layer 3/4 (IP + Port)
        - (l2,l4) layer 2/4 (MAC + Port)
    default: "l2,l3,l4"
    type: str
  descr:
    description:
      - Description for the LAGG interface, for reference only (not parsed except for display).
    default: ""
    type: str
  state:
    description:
      - Whether the LAGG should be present (created/updated) or absent (removed).
    choices: ["present", "absent"]
    default: "present"
    type: str
"""

EXAMPLES = r"""
- name: Create a LAGG (lacp) with igb0 and igb1
  pfsense_lagg:
    laggif: lagg1
    members:
      - igb0
      - igb1
    proto: lacp
    lacptimeout: fast
    lagghash: "l2,l3,l4"
    descr: "WAN-LACP"
    state: present

- name: Remove that LAGG
  pfsense_lagg:
    laggif: lagg1
    members:
      - igb0
      - igb1
    state: absent
"""

RETURN = r"""
commands:
  description: A list of pseudo-CLI commands that the module generated (for debugging purposes).
  returned: always
  type: list
  sample:
    - "create lagg 'lagg1', proto='lacp', members='igb0,igb1'"
    - "update lagg 'lagg1', set proto='failover'"
    - "delete lagg 'lagg1'"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.lagg import (
    PFSenseLaggModule,
    LAGG_ARGUMENT_SPEC
)

def main():
    module = AnsibleModule(
        argument_spec=LAGG_ARGUMENT_SPEC,
        supports_check_mode=True
    )

    pfmodule = PFSenseLaggModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()