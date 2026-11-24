# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import xml.etree.ElementTree as ET

from parameterized import parameterized

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_autoconfigbackup
from .pfsense_module import TestPFSenseModule


PASSWORD = "acb-test-password"
DEVICE_KEY = "0123456789abcdef" * 4
REDACTED = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
EXECACB = "/usr/local/sbin/execacb.php"

SCHEDULE = dict(frequency="cron", minute="44", hour="0", day="*", month="*", dow="*")


class TestPFSenseAutoConfigBackupModule(TestPFSenseModule):
    module = pfsense_autoconfigbackup

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def write_config(self, acb):
        with open(self.tmp_file, "w") as config:
            config.write("<pfsense><version>24.0</version><system><hostname>pfsense</hostname>{0}</system></pfsense>".format(acb))

    def acb_config(self):
        return ET.parse(self.tmp_file).find("system/acb")

    def stored(self):
        return {child.tag: child.text or "" for child in self.acb_config()}

    def test_enable_cron_and_repeat(self):
        self.write_config("")
        params = dict(SCHEDULE, enable=True, numman=20, reverse=True, encryption_password=PASSWORD)
        result = self.run_module(changed=True, **params)
        self.assertEqual(self.stored(), dict(SCHEDULE, enable="yes", numman="20", reverse="yes", encryption_password=PASSWORD))
        self.assertEqual(ET.parse(self.tmp_file).findtext("system/hostname"), "pfsense")
        self.assertNotIn(PASSWORD, repr(result))
        self.assertIn(EXECACB, self.phpshell.call_args[0][0])
        self.assertEqual(self.run_module(**params)["commands"], [])

    def test_enable_with_stored_password(self):
        self.write_config("<acb><enable></enable><frequency>cron</frequency><minute>44</minute><hour>0</hour>"
                          "<encryption_password>{0}</encryption_password><device_key>{1}</device_key></acb>".format(PASSWORD, DEVICE_KEY))
        result = self.run_module(changed=True, enable=True, _ansible_diff=True)
        self.assertEqual(result["commands"], ["update autoconfigbackup acb set enable=True"])
        self.assertEqual(self.stored()["enable"], "yes")
        self.assertEqual(self.stored()["encryption_password"], PASSWORD)
        self.assertEqual(self.stored()["device_key"], DEVICE_KEY)
        for secret in (PASSWORD, DEVICE_KEY):
            self.assertNotIn(secret, repr(result))

    def test_disable_retains_settings(self):
        self.run_module(changed=True, enable=True, encryption_password=PASSWORD, **SCHEDULE)
        result = self.run_module(changed=True, enable=False)
        self.assertEqual(result["commands"], ["update autoconfigbackup acb set enable=False"])
        self.assertEqual(self.stored()["enable"], "")
        self.assertEqual(self.stored()["encryption_password"], PASSWORD)
        self.assertEqual(self.stored()["minute"], "44")

    def test_change_password(self):
        self.run_module(changed=True, enable=True, encryption_password=PASSWORD, **SCHEDULE)
        new_password = "acb-rotated-password"
        result = self.run_module(changed=True, encryption_password=new_password, _ansible_diff=True)
        for password in (PASSWORD, new_password):
            self.assertNotIn(password, repr(result))
        self.assertEqual(result["diff"]["before"]["encryption_password"], REDACTED)
        self.assertEqual(result["diff"]["after"]["encryption_password"], REDACTED)
        self.assertEqual(self.stored()["encryption_password"], new_password)

    def test_every_change_frequency(self):
        self.run_module(changed=True, enable=True, encryption_password=PASSWORD, frequency="every")
        self.assertEqual(self.stored()["frequency"], "every")
        self.assertIn(EXECACB, self.phpshell.call_args[0][0])

    def test_check_mode(self):
        result = self.run_module(changed=True, enable=True, encryption_password=PASSWORD, _ansible_check_mode=True, **SCHEDULE)
        self.assertNotIn(PASSWORD, repr(result))
        self.assertIsNone(self.acb_config())
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()

    def test_untouched_configuration(self):
        self.run_module()
        self.run_module(enable=False)
        self.run_module(reverse=False)
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()

    def test_require_password_to_enable(self):
        with set_module_args(dict(SCHEDULE, enable=True)):
            self.assertIn("encryption_password is required", self.failed()["msg"])
        self.assertFalse(os.path.exists(self.backup_file))

    def test_random_minute_for_cron(self):
        self.run_module(changed=True, frequency="cron", hour="0")
        minute = self.stored()["minute"]
        self.assertTrue(1 <= int(minute) <= 59)
        self.run_module(frequency="cron", hour="0")
        self.assertEqual(self.stored()["minute"], minute)

    def test_new_device_key_when_enabling(self):
        self.run_module(changed=True, enable=True, encryption_password=PASSWORD, **SCHEDULE)
        self.assertIn("$new_key = true;", self.phpshell.call_args[0][0])
        self.assertIn('write_config("AutoConfigBackup settings updated");', self.phpshell.call_args[0][0])
        self.run_module(changed=True, hint="firewall")
        self.assertIn("$new_key = false;", self.phpshell.call_args[0][0])

    def test_legacy_passwords_redacted(self):
        self.write_config("<acb><enable>yes</enable><encryption_password>{0}</encryption_password>"
                          "<gold_password>gold-portal-secret</gold_password>"
                          "<gold_encryption_password>gold-encryption-secret</gold_encryption_password></acb>".format(PASSWORD))
        result = self.run_module(changed=True, hint="firewall", _ansible_diff=True)
        for secret in (PASSWORD, "gold-portal-secret", "gold-encryption-secret"):
            self.assertNotIn(secret, repr(result))
        self.assertEqual(result["diff"]["after"]["gold_password"], REDACTED)

    @parameterized.expand([
        ("minute", dict(minute="5;reboot")), ("minute", dict(minute="0")), ("hour", dict(hour="0 *")),
        ("hour", dict(hour="*/6")), ("dow", dict(dow="mon")), ("day", dict(day="1,15")),
        ("numman", dict(numman=51)), ("numman", dict(numman=-1)), ("numman", dict(numman=True)), ("hint", dict(hint="a" * 256)),
        ("encryption_password", dict(encryption_password="short")),
    ])
    def test_invalid_option(self, option, params):
        with set_module_args(params):
            result = self.failed()
        self.assertIn(option, result["msg"])
        self.assertFalse(os.path.exists(self.backup_file))
