# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from pathlib import Path
import xml.etree.ElementTree as ET

from parameterized import parameterized

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_servicewatchdog
from .pfsense_module import TestPFSenseModule


WATCHDOG_ITEMS = "installedpackages/servicewatchdog/item"
CRON_REFRESH = """
require_once("/usr/local/pkg/servicewatchdog.inc");
servicewatchdog_cron_job();
"""


class TestPFSenseServicewatchdogModule(TestPFSenseModule):
    module = pfsense_servicewatchdog

    def setUp(self):
        super().setUp()
        self.config = Path(self.tmp_file)
        self.config.write_text(
            "<pfsense><version>24.0</version><installedpackages><package><name>Service Watchdog</name></package></installedpackages></pfsense>"
        )
        self.php.return_value = [
            dict(name="syslogd", description="System Logger Daemon", enabled=True, status=False),
            dict(name="openvpn", description="OpenVPN server", mode="server", vpnid=1, id=0),
            dict(name="openvpn", description="Another OpenVPN server", mode="server", vpnid=2, id=1),
            dict(name="openvpn", description="OpenVPN client", mode="client", vpnid="1", id=0),
            dict(name="captiveportal", description="Captive Portal for guests", zone="guest"),
            dict(name="captiveportal", description="Captive Portal for staff", zone="staff"),
        ]

    def run_module(self, changed=False, **params):
        self.php.reset_mock()
        self.phpshell.reset_mock()
        with set_module_args(params):
            return self.changed(changed)

    def entries(self):
        return [{child.tag: child.text or "" for child in entry} for entry in ET.parse(self.config).findall(WATCHDOG_ITEMS)]

    def assert_rejected(self, msg, **params):
        before = self.config.read_bytes()
        with set_module_args(params):
            self.assertIn(msg, self.failed()["msg"])
        self.assertEqual(self.config.read_bytes(), before)
        self.phpshell.assert_not_called()

    def test_create_and_repeat(self):
        expected = dict(name="syslogd", description="System Logger Daemon", notify="")

        def check_saved_config(*args, **kwargs):
            self.assertEqual(self.entries(), [expected])
            return 0, "", ""

        self.phpshell.side_effect = check_saved_config
        result = self.run_module(changed=True, name="syslogd", notify=True)
        self.assertEqual(result["commands"], ["create servicewatchdog 'syslogd', notify=''"])
        self.assertEqual(result["diff"]["after"], expected)
        self.php.assert_called_once()
        self.assertIn("array_values(get_services())", self.php.call_args.args[0])
        self.phpshell.assert_called_once_with(CRON_REFRESH, debug=False)

        before = self.config.read_bytes()
        self.run_module(name="syslogd", notify=True)
        self.assertEqual(self.config.read_bytes(), before)
        self.php.assert_not_called()
        self.phpshell.assert_not_called()

    def test_update_notification(self):
        self.run_module(changed=True, name="syslogd")
        self.assertNotIn("notify", self.entries()[0])
        self.run_module(changed=True, name="syslogd", notify=True)
        self.assertIn("notify", self.entries()[0])
        self.phpshell.assert_called_once_with(CRON_REFRESH, debug=False)
        self.run_module(name="syslogd")
        self.assertIn("notify", self.entries()[0])
        self.run_module(changed=True, name="syslogd", notify=False)
        self.assertNotIn("notify", self.entries()[0])
        self.phpshell.assert_called_once_with(CRON_REFRESH, debug=False)
        self.run_module(name="syslogd", notify=False)
        self.phpshell.assert_not_called()

    def test_check_mode_and_remove_unavailable_service(self):
        before = self.config.read_bytes()
        self.run_module(changed=True, name="syslogd", _ansible_check_mode=True)
        self.assertEqual(self.config.read_bytes(), before)
        self.phpshell.assert_not_called()

        self.run_module(changed=True, name="syslogd")
        before = self.config.read_bytes()
        self.php.return_value = []
        absent = dict(name="syslogd", state="absent")
        self.run_module(changed=True, **absent, _ansible_check_mode=True)
        self.assertEqual(self.config.read_bytes(), before)
        self.php.assert_not_called()
        self.phpshell.assert_not_called()

        result = self.run_module(changed=True, **absent)
        self.assertEqual(result["commands"], ["delete servicewatchdog 'syslogd'"])
        self.assertEqual(self.entries(), [])
        self.php.assert_not_called()
        self.phpshell.assert_called_once_with(CRON_REFRESH, debug=False)
        self.run_module(**absent)
        self.phpshell.assert_not_called()

    @parameterized.expand(
        [
            ("openvpn", dict(mode="server", vpnid=1), dict(mode="client", vpnid=1), "Specify mode and vpnid"),
            ("captiveportal", dict(zone="guest"), dict(zone="staff"), "Specify zone"),
        ]
    )
    def test_select_instance(self, name, first, second, hint):
        self.assert_rejected(hint, name=name)
        self.run_module(changed=True, name=name, **first)
        self.run_module(changed=True, name=name, **second)
        self.assertEqual(len(self.entries()), 2)
        self.phpshell.reset_mock()
        self.assert_rejected(hint, name=name, state="absent")
        self.run_module(changed=True, name=name, notify=True, **second)
        self.assertNotIn("notify", self.entries()[0])
        self.assertIn("notify", self.entries()[1])
        self.run_module(changed=True, name=name, state="absent", **first)
        self.assertEqual(len(self.entries()), 1)
        for field, value in second.items():
            self.assertEqual(self.entries()[0][field], str(value))

    def test_select_openvpn_by_id_within_mode(self):
        self.run_module(changed=True, name="openvpn", mode="server", vpnid=1)
        self.run_module(changed=True, name="openvpn", mode="server", vpnid=2)
        self.assertEqual([entry["vpnid"] for entry in self.entries()], ["1", "2"])
        self.run_module(changed=True, name="openvpn", mode="server", vpnid=2, state="absent")
        self.assertEqual([entry["vpnid"] for entry in self.entries()], ["1"])

    @parameterized.expand(
        [
            ("non-empty service name", dict(name=" ")),
            ("cannot be monitored", dict(name="cron")),
            ("No available service", dict(name="unknown'")),
            ("No available service", dict(name="captiveportal", zone="missing")),
            ("must be supplied together", dict(name="openvpn", mode="server")),
            ("must be supplied together", dict(name="syslogd", vpnid=1, mode="server")),
            ("vpnid must be positive", dict(name="openvpn", vpnid=0, mode="server")),
            ("zone must be", dict(name="syslogd", zone="guest", state="absent")),
        ]
    )
    def test_invalid_input(self, msg, params):
        self.assert_rejected(msg, **params)

    def test_package_missing(self):
        self.config.write_text("<pfsense><version>24.0</version></pfsense>")
        self.assert_rejected("Unable to find package Service Watchdog", name="syslogd")
        self.php.assert_not_called()

    def test_apply_failure_reports_saved_change(self):
        self.phpshell.return_value = 1, "", "PHP error"
        with set_module_args(dict(name="syslogd")):
            result = self.failed()
        self.assertTrue(result["changed"])
        self.assertIn("Failed to update the Service Watchdog cron job", result["msg"])
        self.assertEqual(result["stderr"], "PHP error")
        self.assertEqual(self.entries()[0]["name"], "syslogd")
