# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import re

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import AnsibleExitJson, set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_phpshell

from .pfsense_module import TestPFSenseModule

PROMPT = "pfSense shell: "
MARKER = re.compile(r'echo "\\n" \. "(ansible_[0-9a-f]{16})" \. "([0-9a-f]{16})" \. "\\n";\n')


class TestPFSensePHPShellModule(TestPFSenseModule):
    module = pfsense_phpshell

    def shell(self, output="", changed=True, rc=0, stderr="", runs=True, ends=True, exits=False):
        """act as pfSsh.php: echo each line read, then print what the code prints when it runs"""

        def run(command):
            marker = "".join(MARKER.search(command).groups())
            stdout = "".join(PROMPT + line + "\n" for line in command.split("\n")) + PROMPT + "exec\n"
            if runs:
                stdout += "\n" + marker + "\n" + output
                if ends:
                    stdout += "\n" + marker + json.dumps(dict(changed=changed), separators=(",", ":")) + "\n"
            else:
                stdout += output
            if not exits:
                stdout += PROMPT + "exit\n"
            return (rc, stdout, stderr)

        self.phpshell.side_effect = run

    def run_module(self, cmd="echo 'hostname';", changed=True):
        with set_module_args(dict(cmd=cmd)):
            return self.changed(changed)

    def fail_module(self, cmd="echo 'hostname';"):
        with set_module_args(dict(cmd=cmd)):
            return self.failed()

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
        self.shell("hostname")
        result = self.run_module(cmd)

        self.phpshell.assert_called_once()
        self.assertIn("\n" + cmd + "\n", self.phpshell.call_args[0][0])
        self.assertEqual(result["stdout"], "hostname")
        self.assertEqual(result["rc"], 0)

    def test_output_lines(self):
        self.shell("line 1\nline 2\n")
        self.assertEqual(self.run_module()["stdout"], "line 1\nline 2\n")

    def test_code_reports_no_change(self):
        self.shell(changed=False)
        self.assertEqual(self.run_module("$ansible_changed = false;", changed=False)["stdout"], "")
        self.assertTrue(self.phpshell.call_args[0][0].startswith("$ansible_changed = true;\n"))

    def test_code_exits(self):
        self.shell("partial\n", ends=False, exits=True)
        self.assertEqual(self.run_module()["stdout"], "partial\n")

    def test_code_fails(self):
        self.shell("partial\n", rc=1, ends=False, exits=True)
        result = self.fail_module()
        self.assertEqual(result["rc"], 1)
        self.assertEqual(result["stdout"], "partial\n")

    def test_parse_error(self):
        error = "PHP Parse error:  syntax error, unexpected end of file in /usr/local/sbin/pfSsh.php(370) : eval()'d code on line 4\n"
        self.shell(error, rc=255, runs=False, exits=True)
        result = self.fail_module()
        self.assertEqual(result["rc"], 255)
        self.assertTrue(result["stdout"].startswith(PROMPT + "$ansible_changed = true;\n"))
        self.assertTrue(result["stdout"].endswith(error))

    def test_stderr(self):
        self.shell(stderr="Warning: something")
        self.assertEqual(self.fail_module()["stderr"], "Warning: something")
