# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import xml.etree.ElementTree as ET

from parameterized import parameterized

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_notification_smtp
from .pfsense_module import TestPFSenseModule


class TestPFSenseNotificationSMTPModule(TestPFSenseModule):
    module = pfsense_notification_smtp

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def smtp_config(self):
        return ET.parse(self.tmp_file).find("notifications/smtp")

    def configure_smtp(self):
        self.run_module(changed=True, disable=True, ipaddress="relay.example.com", port=465, timeout=30,
                        ssl=True, sslvalidate=False, fromaddress="firewall@example.com",
                        notifyemailaddress="ops+firewall@example.com, admin@example.net",
                        username="mailer", password="old&secret'123", authmech="LOGIN")

    def test_create_and_repeat(self):
        self.configure_smtp()
        smtp = self.smtp_config()
        self.assertEqual({child.tag: child.text or "" for child in smtp}, dict(
            disable="", ipaddress="relay.example.com", port="465", timeout="30", ssl="", sslvalidate="disabled",
            fromaddress="firewall@example.com", notifyemailaddress="ops+firewall@example.com, admin@example.net",
            username="mailer", password="old&secret'123", authentication_mechanism="LOGIN",
        ))
        result = self.run_module(disable=True, ipaddress="relay.example.com", port=465, timeout=30,
                                 ssl=True, sslvalidate=False, fromaddress="firewall@example.com",
                                 notifyemailaddress="ops+firewall@example.com, admin@example.net",
                                 username="mailer", password="old&secret'123", authmech="LOGIN")
        self.assertEqual(result["commands"], [])

    def test_partial_update_preserves_existing_settings_and_other_notifications(self):
        with open(self.tmp_file, "w") as config:
            config.write("<pfsense><version>24.0</version><notifications><telegram><enable/></telegram>"
                         "<smtp><disable/><ssl/><sslvalidate>disabled</sslvalidate><ipaddress>relay.example.com</ipaddress>"
                         "<notifyemailaddress>admin@example.net</notifyemailaddress><password>stored-password</password>"
                         "</smtp></notifications></pfsense>")
        result = self.run_module(changed=True, disable=False, ssl=False, sslvalidate=True, authmech="LOGIN")
        config = ET.parse(self.tmp_file)
        smtp = config.find("notifications/smtp")
        self.assertEqual({child.tag: child.text for child in smtp}, dict(
            sslvalidate="enabled", ipaddress="relay.example.com", notifyemailaddress="admin@example.net",
            password="stored-password", authentication_mechanism="LOGIN",
        ))
        self.assertIsNotNone(config.find("notifications/telegram/enable"))
        self.assertEqual(result["commands"], ["update notification_smtp smtp set disable=False, ssl=False, sslvalidate='enabled', authmech='LOGIN'"])
        self.assertNotIn("stored-password", repr(result))
        self.run_module(disable=False, ssl=False, sslvalidate=True, authmech="LOGIN")

    def test_password_rotation_redacts_both_values(self):
        self.configure_smtp()
        # Debug mode, so that the trace is written (to the test directory)
        result = self.run_module(changed=True, password="new&secret'456", _ansible_diff=True, _ansible_debug=True)
        with open(self.debug_file) as debug:
            trace = debug.read()
        self.assertNotEqual(trace, "")
        for secret in ("old&secret'123", "new&secret'456"):
            self.assertNotIn(secret, repr(result))
            self.assertNotIn(secret, trace)
        self.assertEqual(self.smtp_config().findtext("password"), "new&secret'456")
        self.assertEqual(result["diff"]["before"]["password"], "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER")
        self.assertEqual(result["diff"]["after"]["password"], "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER")
        self.assertEqual(result["commands"], ["update notification_smtp smtp set password=VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"])

    def test_check_mode(self):
        result = self.run_module(changed=True, disable=True, _ansible_check_mode=True, _ansible_diff=True)
        self.assertEqual(result["diff"]["after"]["sslvalidate"], "enabled")
        self.assertIsNone(self.smtp_config())
        self.assertFalse(os.path.exists(self.backup_file))

    def test_empty_task(self):
        self.run_module()
        self.assertIsNone(self.smtp_config())
        self.assertFalse(os.path.exists(self.backup_file))

    def test_clear_optional_values(self):
        self.configure_smtp()
        self.run_module(changed=True, ipaddress="", fromaddress="", notifyemailaddress="", username="", password="")
        smtp = self.smtp_config()
        for field in ("ipaddress", "fromaddress", "notifyemailaddress", "username", "password"):
            self.assertEqual(smtp.findtext(field), "")

    @parameterized.expand([("192.0.2.8", 1), ("2001:db8::8", 65535), ("relay", 25), ("Relay.Example.com.", 587)])
    def test_valid_server_and_port(self, host, port):
        self.run_module(changed=True, ipaddress=host, port=port, timeout=1)
        self.assertEqual(self.smtp_config().findtext("ipaddress"), host)
        self.assertEqual(self.smtp_config().findtext("port"), str(port))

    @parameterized.expand([
        ("ipaddress", "smtp://relay.example.com"), ("ipaddress", "relay.example.com:25"),
        ("ipaddress", "-relay.example.com"), ("ipaddress", "relay..example.com"),
        ("ipaddress", "192.0.2.256"), ("ipaddress", "2001:db8::1/64"),
        ("ipaddress", "a" * 64 + ".example.com"), ("ipaddress", "relay.example.com\n"),
        ("port", 0), ("port", 65536), ("port", True), ("timeout", 0), ("timeout", -1), ("timeout", True),
        ("fromaddress", "sender"), ("fromaddress", "a@example.com,b@example.com"),
        ("fromaddress", "a..b@example.com"), ("notifyemailaddress", "admin@example.com,broken"),
        ("notifyemailaddress", "admin@example.com,"), ("notifyemailaddress", "admin@example.com,\nops@example.net"),
        ("authmech", "CRAM-MD5"),
    ])
    def test_invalid_option(self, option, value):
        with set_module_args({"disable": True, option: value}):
            self.assertIn(option, self.failed()["msg"])
        self.assertIsNone(self.smtp_config())
        self.assertFalse(os.path.exists(self.backup_file))

    @parameterized.expand([("ipaddress", {"notifyemailaddress": "admin@example.com"}), ("notifyemailaddress", {"ipaddress": "relay"})])
    def test_require_server_and_recipient_when_enabling(self, missing, params):
        with set_module_args(dict(params, disable=False)):
            self.assertIn("{0} is required".format(missing), self.failed()["msg"])
        self.assertIsNone(self.smtp_config())
        self.assertFalse(os.path.exists(self.backup_file))
