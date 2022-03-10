#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021 Chris Morton, cosmo@cosmo.2y.net
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_haproxy_frontend_server
version_added: "2.10"
author: Chris Morton (@cosmosified)
short_description: Manage pfSense haproxy frontend servers
description:
  - Manage pfSense haproxy servers
notes:
options:
  frontend:
    description: The frontend name.
    required: true
    type: str
  extaddr:
    description: The external address [wan_ipv4, lan_ipv4, etc].
    required: true
    type: str
  extaddr_port:
    description: The port
    required: true
    type: str
  extaddr_ssl:
    description: Whether this is listening on ssl
    required: false
    type: str
  state:
    description: State in which to leave the backend server
    choices: [ "present", "absent" ]
    default: present
    type: str
"""

EXAMPLES = """
- name: Add front server ip
  pfsense_haproxy_frontend_server:
    frontend: exchange
    extaddr: wan_ipv4
    port: 443
    extaddr_ssl: yes
    state: present

- name: Remove frontend ip
  pfsense_haproxy_backend_server:
    backend: exchange
    name: exchange.acme.org
    state: absent
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: [
        "create haproxy_backend_server 'exchange.acme.org' on 'exchange', status='active', address='exchange.acme.org', port=443",
        "delete haproxy_backend_server 'exchange.acme.org' on 'exchange'"
    ]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.haproxy_frontend_server import (
    PFSenseHaproxyFrontendServerModule,
    HAPROXY_FRONTEND_SERVER_ARGUMENT_SPEC,
)


def main():
    module = AnsibleModule(
        argument_spec=HAPROXY_FRONTEND_SERVER_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseHaproxyFrontendServerModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
