# Copyright: (c) 2026, Romain Tiennot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import xml.etree.ElementTree as ET

from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import patch
from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_update_settings
from .pfsense_module import TestPFSenseModule


HASH = "$2y$10$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQ"
SYSTEM = (
    "<system><hostname>fw</hostname><user><name>admin</name><bcrypt-hash>{0}</bcrypt-hash></user><pkg_repo_conf_path>26.07.2</pkg_repo_conf_path>{1}</system>"
)
NO_BE = "<firmware><disableautobe></disableautobe></firmware>"
SWITCH = "pkg_switch_repo();"


class TestPFSenseUpdateSettingsModule(TestPFSenseModule):
    module = pfsense_update_settings

    def setUp(self):
        super(TestPFSenseUpdateSettingsModule, self).setUp()
        self.write_config(NO_BE)
        mock_php = patch("ansible_collections.pfsensible.core.plugins.module_utils.pfsense.PFSenseModule.php", return_value=["26.07.2", "26.11"])
        self.php = mock_php.start()
        self.addCleanup(mock_php.stop)

    def write_config(self, firmware):
        with open(self.tmp_file, "w") as config:
            config.write("<pfsense><version>24.0</version>{0}</pfsense>".format(SYSTEM.format(HASH, firmware)))

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def system(self):
        return ET.parse(self.tmp_file).find("system")

    def test_boot_environment_and_repeat(self):
        result = self.run_module(changed=True, disableautobe=False, _ansible_diff=True)
        self.assertEqual(result["commands"], ["update update_settings firmware set disableautobe=False"])
        self.assertIsNone(self.system().find("firmware"))
        self.assertEqual(
            result["diff"], {"before": {"pkg_repo_conf_path": "26.07.2", "firmware": {"disableautobe": ""}}, "after": {"pkg_repo_conf_path": "26.07.2"}}
        )
        self.assertNotIn(HASH, repr(result))
        self.assertEqual(self.system().findtext("user/bcrypt-hash"), HASH)
        self.phpshell.assert_not_called()
        self.assertEqual(self.run_module(disableautobe=False)["commands"], [])

    def test_disable_check(self):
        result = self.run_module(changed=True, disablecheck=True)
        self.assertEqual(result["commands"], ["update update_settings firmware set disablecheck=True"])
        firmware = self.system().find("firmware")
        self.assertIsNotNone(firmware.find("disablecheck"))
        self.assertIsNotNone(firmware.find("disableautobe"))

    def test_branch(self):
        result = self.run_module(changed=True, branch="26.11")
        self.assertEqual(result["commands"], ["update update_settings firmware set branch='26.11'"])
        self.assertEqual(self.system().findtext("pkg_repo_conf_path"), "26.11")
        self.assertIn(SWITCH, self.phpshell.call_args[0][0])
        self.phpshell.reset_mock()
        self.run_module(branch="26.11")
        self.phpshell.assert_not_called()

    def test_unknown_branch(self):
        with set_module_args(dict(branch="2.8.1")):
            self.assertEqual(self.failed()["msg"], "branch 2.8.1 is not one of the firewall's: 26.07.2, 26.11")
        self.assertFalse(os.path.exists(self.backup_file))

    def test_no_option(self):
        self.run_module()
        self.assertFalse(os.path.exists(self.backup_file))

    def test_check_mode(self):
        self.run_module(changed=True, disableautobe=False, disablecheck=True, _ansible_check_mode=True)
        self.assertIsNotNone(self.system().find("firmware/disableautobe"))
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()
