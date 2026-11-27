#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_notification_slack

short_description: Manage pfSense Slack notification configuration

version_added: "0.8.0"

description:
  - Manage pfSense Slack notification configuration.
  - Omitted options preserve existing settings.

options:
  enabled:
    description:
      - Enable Slack notifications. A token and channel must be configured while notifications are enabled.
      - Disabling notifications retains the token and channel.
    type: bool
  api:
    description:
      - Slack API token. It may contain ASCII letters, digits, hyphens, and colons.
      - Set to an empty string to clear the token while notifications are disabled.
    type: str
  channel:
    description:
      - Slack channel name, such as C(firewall). Supply the bare name because pfSense adds the hash prefix.
      - The name may contain up to 80 lowercase ASCII letters, digits, hyphens, and underscores.
      - Set to an empty string to clear the channel while notifications are disabled.
    type: str

author: Orion Poplawski (@opoplawski)
"""

EXAMPLES = r"""
- name: Configure Slack notifications
  pfsensible.core.pfsense_notification_slack:
    enabled: true
    api: "{{ vault_slack_token }}"
    channel: pfsense

- name: Disable Slack notifications and retain the configuration
  pfsensible.core.pfsense_notification_slack:
    enabled: false
"""
RETURN = r"""
commands:
    description: Pseudo-CLI commands describing configuration changes.
    returned: always
    type: list
    elements: str
    sample: ["update notification_slack slack set channel='firewall'"]
"""

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

NOTIFICATION_SLACK_ARGUMENT_SPEC = dict(
    enabled=dict(type="bool"),
    api=dict(type="str", no_log=True),
    channel=dict(type="str"),
)

REDACTED_TOKEN = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"


class PFSenseNotificationSlackModule(PFSenseModuleConfigBase):
    """Manage pfSense Slack notification settings."""

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """return argument spec"""
        return NOTIFICATION_SLACK_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseNotificationSlackModule, self).__init__(
            module,
            pfsense,
            name="pfsense_notification_slack",
            root="notifications",
            node="slack",
            create_root=True,
            bool_style="absent/present",
        )

    def _validate_params(self):
        slack = self.root_elt.find(self.node)
        enabled = self.params.get("enabled")
        if enabled is None:
            enabled = slack is not None and slack.find("enabled") is not None

        for param, pattern, error in (
            ("api", r"[A-Za-z0-9:-]+", "api may contain only ASCII letters, digits, hyphens, and colons"),
            ("channel", r"[a-z0-9_-]{1,80}", "channel must be a bare name of up to 80 lowercase ASCII letters, digits, hyphens, and underscores"),
        ):
            value = self.params.get(param)
            if value is None and enabled and slack is not None:
                value = slack.findtext(param)
            if enabled and value in (None, "", "0"):
                self.module.fail_json(msg="{0} is required when Slack notifications are enabled".format(param))
            if value and not re.fullmatch(pattern, value):
                self.module.fail_json(msg=error)

    def run(self, params):
        if any(value is not None for value in params.values()):
            super(PFSenseNotificationSlackModule, self).run(params)

    def _run_post(self):
        # Ansible only knows the token supplied with this task, which may differ from the stored token.
        for snapshot in self.diff.values():
            if snapshot.get("api"):
                snapshot["api"] = REDACTED_TOKEN

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """return obj's name"""
        return "slack"

    def format_cli_field(self, after, field, *args, **kwargs):
        if field == "api" and after.get(field):
            after = dict(after, api=REDACTED_TOKEN)
        return super(PFSenseNotificationSlackModule, self).format_cli_field(after, field, *args, **kwargs)


def main():
    module = AnsibleModule(argument_spec=NOTIFICATION_SLACK_ARGUMENT_SPEC, supports_check_mode=True)

    pfmodule = PFSenseNotificationSlackModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
