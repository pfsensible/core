#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_notification_slack

short_description: Manage pfSense Slack notification configuration

version_added: "0.7.2"

description:
  - Manage pfSense Slack notification configuration.

options:
  enabled:
    description: Enable Slack Notifications.
    type: bool
  api:
    description: Slack API Key.
    type: str
  channel:
    description: Slack channel name that will be used to send the notifications to.
    type: str

author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Configure Slack notifications
  pfsensible.core.pfsense_notification_slack:
    enabled: true
    api: API_KEY
    channel: pfsense
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: ["update notification_slack set ..."]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

NOTIFICATION_SLACK_ARGUMENT_SPEC = dict(
    enabled=dict(type='bool'),
    api=dict(type='str', no_log=True),
    channel=dict(type='str'),
)


class PFSenseNotificationSlackModule(PFSenseModuleConfigBase):
    """ module managing pfsense advanced_notification configuration """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return NOTIFICATION_SLACK_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseNotificationSlackModule, self).__init__(module, pfsense, root='notifications', node='slack', create_root=True, bool_style='absent/present')

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "notification_slack"


def main():
    module = AnsibleModule(
        argument_spec=NOTIFICATION_SLACK_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseNotificationSlackModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
