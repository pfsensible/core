#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1",
                    "status": ["preview"],
                    "supported_by": "community"}

DOCUMENTATION = """
---
module: pfsense_rule
version_added: 0.1.0
author: Orion Poplawski (@opoplawski), Frederic Bor (@f-bor)
short_description: Manage pfSense firewall rules
description:
  - Manage pfSense firewall rules
notes:
  - Omitted settings retain their values on existing rules. Specify O(floating=true) to select a floating rule.
options:
  name:
    description: The name the rule
    required: true
    type: str
  action:
    description: The action of the rule. New rules default to C(pass).
    choices: [ "pass", "block", "match", "reject" ]
    type: str
  state:
    description: State in which to leave the rule
    default: present
    choices: [ "present", "absent" ]
    type: str
  disabled:
    description: Whether the rule is disabled. New rules are enabled by default.
    type: bool
  interface:
    description: The interface for the rule. Use 'any' to apply to all interface (for floating rules only).
    required: true
    type: str
  floating:
    description: Whether the rule is floating. Omit for interface rules.
    type: bool
  direction:
    description: Direction the floating rule applies to. Required when creating a floating rule.
    choices: [ "any", "in", "out" ]
    type: str
  ipprotocol:
    description: The IP protocol. New rules default to C(inet).
    choices: [ "inet", "inet46", "inet6" ]
    type: str
  protocol:
    description:
      - The protocol. Set to C(any) to match any protocol, which is the default for new rules.
      - Switching to a protocol that does not support ports clears existing ports.
    choices: [ "any", "tcp", "udp", "tcp/udp", "icmp", "igmp", "ospf", "esp", "ah", "gre", "pim", "sctp", "pfsync", "carp" ]
    type: str
  source:
    description:
      - The source address, in [!]{IP,HOST,ALIAS,any,(self),IP:INTERFACE,NET:INTERFACE} format. Required when creating a rule.
      - You can use a virtual IP description in place of its address.
    type: str
  source_port:
    description:
      - Source port or port range specification.
      - This can either be a alias or a port number.
      - An inclusive range can also be specified using C(first-last). Set to C(any) to clear the port.
    type: str
  destination:
    description:
      - The destination address, in [!]{IP,HOST,ALIAS,any,(self),IP:INTERFACE,NET:INTERFACE} format. Required when creating a rule.
      - You can use a virtual IP description in place of its address.
    type: str
  destination_port:
    description:
      - Destination port or port range specification.
      - This can either be a alias or a port number.
      - An inclusive range can also be specified using C(first-last). Set to C(any) to clear the port.
    type: str
  log:
    description: Log packets matched by rule
    type: bool
  after:
    description: Rule to go after, or C(top)
    type: str
  before:
    description: Rule to go before, or C(bottom)
    type: str
  tcpflags_any:
    description: Allow TCP packets with any flags set.
    type: bool
  statepolicy:
    description: >
        State policy. Optionally overrides the default state policy behavior to force a specific policy for connections matching this rule. Only effective when
        rules keep state. The global default policy option is located at System > Advanced, Firewall & NAT tab.
    choices: ["", "if-bound", "floating"]
    type: str
    version_added: 0.8.0
  statetype:
    description: State type. New rules default to C(keep state).
    choices: ["keep state", "sloppy state", "synproxy state", "none"]
    type: str
  queue:
    description: QoS default queue. Set to an empty string to clear.
    type: str
  ackqueue:
    description: QoS acknowledge queue. Set to an empty string to clear.
    type: str
  in_queue:
    description: Limiter queue for incoming traffic. Set to an empty string to clear.
    type: str
  out_queue:
    description: Limiter queue for outgoing traffic. Set to an empty string to clear.
    type: str
  queue_error:
    description: Raise an error if a specified queue is missing
    type: bool
    default: True
  gateway:
    description: Set to C(default) to use the system routing table, the default for new rules. Choose a gateway to use policy-based routing.
    type: str
  tracker:
    description: Rule tracking ID. Defaults to timestamp of rule creation and not modified if not set or set to 0.
    type: str
  icmptype:
    description:
      - One or more of these ICMP subtypes may be specified, separated by comma, or C(any) for all of them.
      - The types must match the IP protocol. New ICMP rules default to C(any).
      - althost, dataconv, echorep, echoreq, fqdnrep, fqdnreq, groupqry, grouprep, groupterm, inforep, inforeq, ipv6-here,
      - ipv6-where, listendone, listenrep, listqry, maskrep, maskreq, mobredir, mobregrep, mobregreq, mtrace, mtraceresp,
      - neighbradv, neighbrsol, niqry, nirep, paramprob, photuris, redir, routeradv, routersol, routrrenum, skip, squench,
      - timerep, timereq, timex, toobig, trace, unreach, wrurep, wrureq
    type: str
  sched:
    description: Schedule for when the rule is active. Set to an empty string to clear.
    required: False
    type: str
  quick:
    description: Apply the action of a floating rule immediately. Set to V(false) to clear. New rules default to V(false).
    type: bool
"""

EXAMPLES = """
- name: "Add Internal DNS out rule"
  pfsense_rule:
    name: 'Allow Internal DNS traffic out'
    action: pass
    interface: lan
    ipprotocol: inet
    protocol: udp
    source: dns_int
    destination: any
    destination_port: 53
    after: 'Allow proxies out'
    state: present
- name: "Allow inbound port range"
  pfsense_rule:
    name: 'Allow inbound port range'
    action: pass
    interface: wan
    ipprotocol: inet
    protocol: tcp
    source: any
    destination: NET:lan
    destination_port: 4000-5000
    after: 'Allow Internal DNS traffic out'
    state: present
"""

RETURN = """

"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.rule import PFSenseRuleModule, RULE_ARGUMENT_SPEC


def main():
    module = AnsibleModule(
        argument_spec=RULE_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseRuleModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
