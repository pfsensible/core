# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import xml.etree.ElementTree as ET

from parameterized import parameterized

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_notification_slack
from .pfsense_module import TestPFSenseModule


TOKEN = "xoxb-test-123:ABC"
REDACTED = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"


class TestPFSenseNotificationSlackModule(TestPFSenseModule):
    module = pfsense_notification_slack

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def slack_config(self):
        return ET.parse(self.tmp_file).find("notifications/slack")

    def test_create_and_repeat(self):
        params = dict(enabled=True, api=TOKEN, channel="fw-alerts_2")
        result = self.run_module(changed=True, **params)
        slack = self.slack_config()
        self.assertEqual({child.tag: child.text or "" for child in slack}, dict(enabled="", api=TOKEN, channel="fw-alerts_2"))
        self.assertNotIn(TOKEN, repr(result))
        self.assertEqual(result["diff"]["after"]["api"], REDACTED)
        self.assertEqual(self.run_module(**params)["commands"], [])

    def test_disable_and_reenable_using_stored_settings(self):
        with open(self.tmp_file, "w") as config:
            config.write("<pfsense><version>24.0</version><notifications><smtp><disable/></smtp>"
                         "<slack><enabled/><api>{0}</api><channel>firewall</channel></slack></notifications></pfsense>".format(TOKEN))

        result = self.run_module(changed=True, enabled=False)
        config = ET.parse(self.tmp_file)
        self.assertIsNotNone(config.find("notifications/smtp/disable"))
        self.assertIsNone(config.find("notifications/slack/enabled"))
        self.assertEqual(config.findtext("notifications/slack/api"), TOKEN)
        self.assertEqual(config.findtext("notifications/slack/channel"), "firewall")
        self.assertNotIn(TOKEN, repr(result))
        self.assertEqual(result["commands"], ["update notification_slack slack set enabled=False"])
        self.run_module(enabled=False)
        self.run_module(changed=True, enabled=True)
        self.assertIsNotNone(self.slack_config().find("enabled"))

    def test_rotate_token_and_update_channel_independently(self):
        self.run_module(changed=True, enabled=True, api=TOKEN, channel="firewall")
        new_token = "xoxb-rotated-XYZ"
        result = self.run_module(changed=True, api=new_token, _ansible_diff=True)
        for token in (TOKEN, new_token):
            self.assertNotIn(token, repr(result))
        self.assertEqual(result["diff"]["before"]["api"], REDACTED)
        self.assertEqual(result["diff"]["after"]["api"], REDACTED)
        self.assertEqual(result["commands"], ["update notification_slack slack set api='" + REDACTED + "'"])
        self.assertEqual(self.slack_config().findtext("api"), new_token)
        self.assertEqual(self.slack_config().findtext("channel"), "firewall")
        self.run_module(changed=True, channel="a" * 80)
        self.assertEqual(self.slack_config().findtext("channel"), "a" * 80)
        self.assertEqual(self.slack_config().findtext("api"), new_token)

    def test_stage_and_clear_while_disabled(self):
        self.run_module(changed=True, channel="firewall")
        self.assertIsNone(self.slack_config().find("enabled"))
        self.run_module(changed=True, enabled=True, api=TOKEN)
        self.run_module(changed=True, enabled=False, api="", channel="")
        slack = self.slack_config()
        self.assertIsNone(slack.find("enabled"))
        self.assertEqual(slack.findtext("api"), "")
        self.assertEqual(slack.findtext("channel"), "")

    def test_check_mode(self):
        result = self.run_module(changed=True, enabled=True, api=TOKEN, channel="firewall", _ansible_check_mode=True, _ansible_diff=True)
        self.assertEqual(result["diff"]["after"]["channel"], "firewall")
        self.assertNotIn(TOKEN, repr(result))
        self.assertIsNone(self.slack_config())
        self.assertFalse(os.path.exists(self.backup_file))

    def test_untouched_configuration(self):
        self.run_module()
        self.run_module(enabled=False)
        self.assertIsNone(self.slack_config())
        self.assertFalse(os.path.exists(self.backup_file))

    @parameterized.expand([
        ("api", "https://hooks.slack.com/services/example"), ("api", "xoxb-fake_token"), ("api", "xoxb-fake\n"),
        ("channel", "#firewall"), ("channel", "Firewall"), ("channel", "firewall alerts"),
        ("channel", "a" * 81), ("channel", "firewall\n"),
    ])
    def test_invalid_option(self, option, value):
        with set_module_args({"enabled": False, option: value}):
            result = self.failed()
        self.assertIn(option, result["msg"])
        self.assertNotIn(value, repr(result))
        self.assertFalse(os.path.exists(self.backup_file))

    @parameterized.expand([
        ("api", {"channel": "firewall"}), ("channel", {"api": TOKEN}),
        ("api", {"api": "0", "channel": "firewall"}), ("channel", {"api": TOKEN, "channel": "0"}),
    ])
    def test_require_token_and_channel_when_enabled(self, option, params):
        with set_module_args(dict(params, enabled=True)):
            self.assertIn("{0} is required".format(option), self.failed()["msg"])
        self.assertFalse(os.path.exists(self.backup_file))

    @parameterized.expand([("api",), ("channel",)])
    def test_reject_clearing_settings_while_enabled(self, option):
        self.run_module(changed=True, enabled=True, api=TOKEN, channel="firewall")
        with set_module_args({option: ""}):
            result = self.failed()
        self.assertIn("{0} is required".format(option), result["msg"])
        self.assertNotIn(TOKEN, repr(result))
        self.assertIsNotNone(self.slack_config().find("enabled"))
        self.assertEqual(self.slack_config().findtext("api"), TOKEN)
        self.assertEqual(self.slack_config().findtext("channel"), "firewall")
