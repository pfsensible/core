#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2023, Nicolas Zagulajew <github@xoop.org>

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: pfsense_default_gateway
version_added: 0.6.0
author: "Nicolas Zagulajew (@freeeflyer)"
short_description: Manage pfSense default gateway
description: Check and update pfSense default gateway
notes:
options:
  gateway:
    description: Default gateway name
    required: false
    type: str
  ipprotocol:
    description: Choose the Internet Protocol Version for this gateway.
    required: false
    choices: [ "inet", "inet6" ]
    default: inet
    type: str
"""

EXAMPLES = """
- name: Sets default gateway to automatic
  pfsense_default_gateway:
    gateway: automatic
    ipprotocol: inet

- name: Remove gateway (ie setting it to None)
  pfsense_default_gateway:
    gateway: none
    ipprotocol: inet

- name: return gateways
  pfsense_default_gateway:

"""

RETURN = """
defaultgw4:
    description: default gateway for ipv4
    returned: always
    type: str
    sample: INTERNET_GW4
defaultgw6:
    description: default gateway for ipv6
    returned: always
    type: str
    sample: INTERNET_GW4
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI). If state=read, also returns defaultgw4 and defaultgw6.
    returned: always
    type: list
    sample: [update default_gateway name='my_gw', protocol='inet6' ]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.default_gateway import (
    PFSenseDefaultGatewayModule,
    DEFAULT_GATEWAY_ARGUMENT_SPEC,
)


def main():
    module = AnsibleModule(
        argument_spec=DEFAULT_GATEWAY_ARGUMENT_SPEC, supports_check_mode=True
    )

    pfmodule = PFSenseDefaultGatewayModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
