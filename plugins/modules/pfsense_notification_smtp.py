#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_notification_smtp

short_description: Manage pfSense SMTP notification configuration

version_added: "0.7.2"

description:
  - Manage pfSense SMTP notification configuration.

options:
  disable:
    description: Disable SMTP Notifications.
    type: bool
  ipaddress:
    description: FQDN or IP address of the SMTP E-Mail server to which notifications will be sent.
    type: str
  port:
    description: Port of the SMTP E-Mail server, typically 25, 587 (submission) or 465 (smtps).
    type: int
  timeout:
    description: Connection timeout in seconds to wait for the SMTP server to connect. Default is 20s.
    type: int
  ssl:
    description: Enable SMTP over SSL/TLS.
    type: bool
  sslvalidate:
    description: >
      Validate the SSL/TLS certificate presented by the server. When disabled, the server certificate will not be validated. Encryption will still be used if
      available, but the identity of the server will not be confirmed.
    type: bool
  fromaddress:
    description: This is the e-mail address that will appear in the from field.
    type: str
  notifyemailaddress:
    description: The e-mail address to send email notifications to.
    type: str
  username:
    description: The username for SMTP authentication.
    type: str
  password:
    description: The password for SMTP authentication.
    type: str
  authmech:
    description: The authentication mechanism used by the SMTP server. Most work with PLAIN, some servers like Exchange or Office365 might require LOGIN.
    choices: ['PLAIN', 'LOGIN']
    type: str

author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Configure SMTP notification
  pfsensible.core.pfsense_notification_smtp:
    ipaddress: smtp.example.com
    port:  25
    ssl: true
    sslvalidate: true
    fromaddress: pfsense@example.com
    notifyemailaddress: admin@example.com
    username: smtpuser
    password: smtppass
    authmech: PLAIN
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: ["update notification_smtp set ..."]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

# TOOD - fix handling of disable/sslvalidate as they are each different
NOTIFICATION_SMTP_ARGUMENT_SPEC = dict(
    disable=dict(type='bool'),
    ipaddress=dict(type='str'),
    port=dict(type='int'),
    timeout=dict(type='int'),
    ssl=dict(type='bool'),
    sslvalidate=dict(type='bool'),
    fromaddress=dict(type='str'),
    notifyemailaddress=dict(type='str'),
    username=dict(type='str'),
    password=dict(type='str', no_log=True),
    authmech=dict(type='str', choices=['PLAIN', 'LOGIN']),
)

NOTIFICATION_SMTP_CREATE_DEFAULT = dict(
    tls='',
    username='',
    password='',
    authentication_mechanism='PLAIN',
    sslvalidate='enabled',
    timeout='',
)


class PFSenseNotificationSMTPModule(PFSenseModuleConfigBase):
    """ module managing pfsense advanced_notification configuration """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return NOTIFICATION_SMTP_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseNotificationSMTPModule, self).__init__(module, pfsense, root='notifications', node='smtp', create_root=True, bool_style="absent/present",
                                                            create_default=NOTIFICATION_SMTP_CREATE_DEFAULT)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "notification_smtp"


def main():
    module = AnsibleModule(
        argument_spec=NOTIFICATION_SMTP_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseNotificationSMTPModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
