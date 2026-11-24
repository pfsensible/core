# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import AnsibleExitJson, set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_phpshell

from .pfsense_module import TestPFSenseModule


class TestPFSensePHPShellModule(TestPFSenseModule):
    module = pfsense_phpshell

    def test_check_mode_skips_php(self):
        with set_module_args(dict(cmd="exit(0);", _ansible_check_mode=True)):
            with self.assertRaises(AnsibleExitJson) as exc:
                self.module.main()

        result = exc.exception.args[0]
        self.assertTrue(result["skipped"])
        self.assertFalse(result.get("changed", False))
        self.phpshell.assert_not_called()

    def test_normal_mode_executes_php_and_reports_changed(self):
        cmd = "echo 'hostname';"
        self.phpshell.return_value = (0, "hostname", "")
        with set_module_args(dict(cmd=cmd)):
            result = self.changed(True)

        self.phpshell.assert_called_once_with(cmd)
        self.assertEqual(result["stdout"], "hostname")
