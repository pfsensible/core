# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import xml.etree.ElementTree as ET

from parameterized import parameterized

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_freeradius_sync
from .pfsense_module import TestPFSenseModule


PASSWORD = "sync-test-password"
REDACTED = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
PACKAGE = "<package><name>freeradius3</name><internal_name>radiusd</internal_name></package>"
MANUAL = ("<freeradiussync><config><varsyncenablexmlrpc>manual</varsyncenablexmlrpc><varsynctimeout>150</varsynctimeout>"
          "<row><varsyncdestinenable>ON</varsyncdestinenable><varsyncprotocol>https</varsyncprotocol>"
          "<varsyncipaddress>192.168.4.2</varsyncipaddress><varsyncport>443</varsyncport>"
          "<varsyncusername>admin</varsyncusername><varsyncpassword>{0}</varsyncpassword></row></config></freeradiussync>").format(PASSWORD)


class TestPFSenseFreeRADIUSSyncModule(TestPFSenseModule):
    module = pfsense_freeradius_sync

    def setUp(self):
        super(TestPFSenseFreeRADIUSSyncModule, self).setUp()
        self.write_config(PACKAGE)

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def write_config(self, packages):
        with open(self.tmp_file, "w") as config:
            config.write("<pfsense><version>24.0</version><installedpackages>{0}</installedpackages></pfsense>".format(packages))

    def sync_config(self):
        return ET.parse(self.tmp_file).find("installedpackages/freeradiussync/config")

    def test_auto_removes_manual_targets(self):
        self.write_config(PACKAGE + MANUAL)
        result = self.run_module(changed=True, mode="auto", targets=[], _ansible_diff=True)
        self.assertEqual(result["commands"], ["update freeradius_sync xmlrpc set mode='auto', targets=''"])
        config = self.sync_config()
        self.assertEqual(config.findtext("varsyncenablexmlrpc"), "auto")
        self.assertEqual(config.findtext("varsynctimeout"), "150")
        self.assertIsNone(config.find("row"))
        self.assertNotIn(PASSWORD, repr(result))
        self.assertEqual(self.run_module(mode="auto", targets=[])["commands"], [])

    def test_create_manual_and_repeat(self):
        params = dict(mode="manual", timeout=60, targets=[dict(address="192.168.4.2", password=PASSWORD)])
        result = self.run_module(changed=True, **params)
        self.assertEqual(result["commands"], ["update freeradius_sync xmlrpc set mode='manual', timeout='60', targets='https://192.168.4.2:443'"])
        row = self.sync_config().find("row")
        self.assertEqual({child.tag: child.text for child in row}, dict(
            varsyncdestinenable="ON", varsyncprotocol="https", varsyncipaddress="192.168.4.2", varsyncport="443",
            varsyncusername="admin", varsyncpassword=PASSWORD))
        self.assertNotIn(PASSWORD, repr(result))
        self.assertIn("freeradius_sync_on_changes();", self.phpshell.call_args[0][0])
        self.phpshell.reset_mock()
        self.assertEqual(self.run_module(**params)["commands"], [])
        self.phpshell.assert_not_called()

    def test_change_target_password(self):
        self.write_config(PACKAGE + MANUAL)
        new_password = "sync-rotated-password"
        result = self.run_module(changed=True, targets=[dict(address="192.168.4.2", password=new_password)], _ansible_diff=True)
        self.assertEqual(result["commands"], ["update freeradius_sync xmlrpc set targets='https://192.168.4.2:443 (updated)'"])
        for password in (PASSWORD, new_password):
            self.assertNotIn(password, repr(result))
        self.assertEqual(result["diff"]["before"]["row"]["varsyncpassword"], REDACTED)
        self.assertEqual(result["diff"]["after"]["row"]["varsyncpassword"], REDACTED)
        self.assertEqual(self.sync_config().findtext("row/varsyncpassword"), new_password)

    def test_disabled_target(self):
        params = dict(mode="manual", targets=[
            dict(address="192.168.4.2", password=PASSWORD), dict(address="fw2.example.com", port=8443, password=PASSWORD, enabled=False)])
        self.run_module(changed=True, **params)
        rows = self.sync_config().findall("row")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].findtext("varsyncdestinenable"), "ON")
        self.assertIsNone(rows[1].find("varsyncdestinenable"))
        self.assertEqual(rows[1].findtext("varsyncport"), "8443")
        self.assertEqual(self.run_module(**params)["commands"], [])

    def test_fewer_targets(self):
        self.run_module(changed=True, mode="manual", targets=[
            dict(address="192.168.4.2", password=PASSWORD), dict(address="192.168.4.3", password=PASSWORD)])
        result = self.run_module(changed=True, targets=[dict(address="192.168.4.3", password=PASSWORD)])
        self.assertEqual(result["commands"], ["update freeradius_sync xmlrpc set targets='https://192.168.4.3:443'"])
        rows = self.sync_config().findall("row")
        self.assertEqual([row.findtext("varsyncipaddress") for row in rows], ["192.168.4.3"])

    def test_mode_only_keeps_targets(self):
        self.write_config(PACKAGE + MANUAL)
        result = self.run_module(changed=True, mode="disabled")
        self.assertEqual(result["commands"], ["update freeradius_sync xmlrpc set mode='disabled'"])
        self.assertEqual(self.sync_config().findtext("row/varsyncpassword"), PASSWORD)

    def test_check_mode(self):
        self.write_config(PACKAGE + MANUAL)
        result = self.run_module(changed=True, mode="auto", targets=[], _ansible_check_mode=True, _ansible_diff=True)
        self.assertNotIn(PASSWORD, repr(result))
        self.assertEqual(self.sync_config().findtext("varsyncenablexmlrpc"), "manual")
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()

    def test_untouched_configuration(self):
        self.run_module()
        self.assertIsNone(self.sync_config())
        self.assertFalse(os.path.exists(self.backup_file))

    def test_package_not_installed(self):
        self.write_config("")
        with set_module_args(dict(mode="auto")):
            self.assertIn("Unable to find package freeradius3", self.failed()["msg"])

    def test_manual_requires_targets(self):
        with set_module_args(dict(mode="manual")):
            self.assertIn("targets are required", self.failed()["msg"])
        self.assertFalse(os.path.exists(self.backup_file))

    @parameterized.expand([
        ("timeout", dict(timeout=0)),
        ("timeout", dict(timeout=True)),
        ("port", dict(targets=[dict(address="192.168.4.2", port=70000, password=PASSWORD)])),
        ("port", dict(targets=[dict(address="192.168.4.2", port=True, password=PASSWORD)])),
        ("address", dict(targets=[dict(address="", password=PASSWORD)])),
    ])
    def test_invalid_option(self, option, params):
        with set_module_args(params):
            result = self.failed()
        self.assertIn(option, result["msg"])
        self.assertNotIn(PASSWORD, repr(result))
        self.assertFalse(os.path.exists(self.backup_file))
