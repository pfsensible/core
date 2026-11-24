#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_notification_smtp

short_description: Manage pfSense SMTP notification configuration

version_added: "0.8.0"

description:
  - Manage pfSense SMTP notification configuration.
  - Omitted options preserve existing settings.

options:
  disable:
    description:
      - Disable SMTP notifications while retaining the settings.
      - To explicitly enable notifications, an SMTP server and at least one recipient must be configured.
    type: bool
  ipaddress:
    description: Hostname or IP address of the SMTP server. Set to an empty string to clear it.
    type: str
  port:
    description: SMTP server port from 1 to 65535. pfSense uses 25 if no port is configured.
    type: int
  timeout:
    description: Connection timeout in seconds. Supply a positive integer. pfSense uses 20 seconds if no timeout is configured.
    type: int
  ssl:
    description: Connect using implicit SSL/TLS (typically port 465). Leave disabled for ports that use STARTTLS.
    type: bool
  sslvalidate:
    description: Verify the SMTP server's identity using its SSL/TLS certificate.
    type: bool
  fromaddress:
    description: Sender email address. Set to an empty string to use the firewall's default sender.
    type: str
  notifyemailaddress:
    description: Recipient email address or comma-separated list of addresses. Set to an empty string to clear it.
    type: str
  username:
    description: The username for SMTP authentication. An empty username or password disables SMTP authentication.
    type: str
  password:
    description: The password for SMTP authentication. An empty username or password disables SMTP authentication.
    type: str
  authmech:
    description: The authentication mechanism used by the SMTP server. pfSense uses PLAIN if no mechanism is configured.
    choices: ['PLAIN', 'LOGIN']
    type: str

author: Orion Poplawski (@opoplawski)
"""

EXAMPLES = r"""
- name: Configure SMTP notification
  pfsensible.core.pfsense_notification_smtp:
    disable: false
    ipaddress: smtp.example.com
    port: 465
    ssl: true
    sslvalidate: true
    fromaddress: pfsense@example.com
    notifyemailaddress: admin@example.com
    username: smtpuser
    password: "{{ vault_smtp_password }}"
    authmech: PLAIN

- name: Disable SMTP notifications and retain the configuration
  pfsensible.core.pfsense_notification_smtp:
    disable: true
"""
RETURN = r"""
commands:
    description: Pseudo-CLI commands describing configuration changes.
    returned: always
    type: list
    elements: str
    sample: ["update notification_smtp smtp set port='465'"]
"""

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

NOTIFICATION_SMTP_ARGUMENT_SPEC = dict(
    disable=dict(type="bool"),
    ipaddress=dict(type="str"),
    port=dict(type="int"),
    timeout=dict(type="int"),
    ssl=dict(type="bool"),
    sslvalidate=dict(type="bool"),
    fromaddress=dict(type="str"),
    notifyemailaddress=dict(type="str"),
    username=dict(type="str"),
    password=dict(type="str", no_log=True),
    authmech=dict(type="str", choices=["PLAIN", "LOGIN"]),
)

HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
EMAIL_LOCAL_PART = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*")
REDACTED_PASSWORD = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"


def _valid_hostname(hostname):
    if hostname.endswith("."):
        hostname = hostname[:-1]
    return len(hostname) <= 253 and all(HOST_LABEL.fullmatch(label) for label in hostname.split("."))


def _valid_email(address):
    local, separator, domain = address.rpartition("@")
    return (bool(separator) and len(address) <= 254 and len(local) <= 64 and EMAIL_LOCAL_PART.fullmatch(local) is not None
            and "." in domain and not domain.endswith(".") and _valid_hostname(domain))


class PFSenseNotificationSMTPModule(PFSenseModuleConfigBase):
    """Manage pfSense SMTP notification settings."""

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return NOTIFICATION_SMTP_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseNotificationSMTPModule, self).__init__(
            module, pfsense, name="pfsense_notification_smtp", root="notifications", node="smtp", create_root=True,
            map_param=[("authmech", "authentication_mechanism")], bool_style="absent/present",
            bool_values={"sslvalidate": ("disabled", "enabled")},
            create_default=dict(authentication_mechanism="PLAIN", sslvalidate="enabled"),
        )

    def _find_target(self):
        return self.root_elt.find(self.node)

    def _validate_params(self):
        host = self.params.get("ipaddress")
        if host and not (self.pfsense.is_ipv4_address(host) or ("%" not in host and self.pfsense.is_ipv6_address(host))
                         or (_valid_hostname(host) and not re.fullmatch(r"[0-9.]+", host))):
            self.module.fail_json(msg="ipaddress must be a hostname or an IPv4 or IPv6 address")

        port = self.params.get("port")
        if port is not None and (isinstance(port, bool) or not 1 <= port <= 65535):
            self.module.fail_json(msg="port must be an integer between 1 and 65535")

        timeout = self.params.get("timeout")
        if timeout is not None and (isinstance(timeout, bool) or timeout <= 0):
            self.module.fail_json(msg="timeout must be a positive integer")

        sender = self.params.get("fromaddress")
        if sender and not _valid_email(sender):
            self.module.fail_json(msg="fromaddress must be a valid email address")

        recipients = self.params.get("notifyemailaddress")
        if recipients and ("\r" in recipients or "\n" in recipients
                           or not all(_valid_email(address.strip(" \t")) for address in recipients.split(","))):
            self.module.fail_json(msg="notifyemailaddress must be a comma-separated list of valid email addresses")

        if self.params.get("disable") is False:
            smtp = self._find_target()
            for param in ("ipaddress", "notifyemailaddress"):
                value = self.params.get(param)
                if value is None and smtp is not None:
                    value = smtp.findtext(param)
                if not value or not value.strip():
                    self.module.fail_json(msg="{0} is required to enable SMTP notifications".format(param))

    def run(self, params):
        if any(value is not None for value in params.values()):
            super(PFSenseNotificationSMTPModule, self).run(params)

    def _run_post(self):
        # Ansible's no_log only knows the supplied password, which may differ from the stored one.
        for snapshot in self.diff.values():
            if snapshot.get("password"):
                snapshot["password"] = REDACTED_PASSWORD

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "smtp"

    def _log_fields(self, before=None):
        after = self.diff["after"]
        fields = []
        xml_keys = dict(self.map_param)
        for param in self.argument_spec:
            key = xml_keys.get(param, param)
            if before is not None and after.get(key) == before.get(key):
                continue
            if param == "password":
                if before is not None or after.get(key):
                    fields.append("password=" + REDACTED_PASSWORD)
                continue
            if param in ("disable", "ssl"):
                if key in after or before is not None:
                    fields.append("{0}={1}".format(param, key in after))
                continue
            field = self.format_cli_field(after, key, fname=param, log_none=before is not None, add_comma=False)
            if field:
                fields.append(field)
        if before is None and fields:
            return ", " + ", ".join(fields)
        return ", ".join(fields)


def main():
    module = AnsibleModule(
        argument_spec=NOTIFICATION_SMTP_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseNotificationSMTPModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
