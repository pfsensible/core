#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, genofire <geno+dev@fireorbit.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {"metadata_version": "1.1",
                    "status": ["preview"],
                    "supported_by": "community"}

DOCUMENTATION = """
---
module: pfsense_phpshell
version_added: 0.7.0
author: Geno (@genofire)
short_description: PHP Shell
description:
  - Run PHP code in the pfSense shell.
  - Successful runs report C(changed=true) by default. The code can set C($ansible_changed = false;) when it changed nothing, or
    the task can set C(changed_when) to report changes according to the script's behavior.
  - For read-only scripts, set C(changed_when=false) on the task.
options:
  cmd:
    description: PHP Code to run
    required: true
    type: str
attributes:
  check_mode:
    description: Ansible skips the task in check mode without executing the PHP code.
    support: none
notes:
  - Setting C(check_mode=false) on a task executes the script normally, even during a check-mode playbook run.
  - In such a task, C(ansible_check_mode) still tells whether the playbook runs in check mode. The code can get it from the task,
    to only report what it would change. See the examples.
"""

EXAMPLES = """
- name: run phpshell with code pfSense config.xml
  pfsense_phpshell:
    cmd: |
      require_once("filter.inc");
      require_once("squid.inc");
      squid_resync("yes");

- name: Read the pfSense hostname
  pfsensible.core.pfsense_phpshell:
    cmd: |
      global $config;
      echo $config['system']['hostname'], PHP_EOL;
  changed_when: false

- name: Set the time zone when it differs, and only report it in check mode
  pfsensible.core.pfsense_phpshell:
    cmd: |
      require_once("system.inc");
      $dry_run = {{ ansible_check_mode | ternary('true', 'false') }};
      $ansible_changed = config_get_path("system/timezone") != "Europe/Paris";
      if ($ansible_changed && !$dry_run) {
          config_set_path("system/timezone", "Europe/Paris");
          write_config("Set the time zone");
          system_timezone_configure();
      }
  check_mode: false
"""

RETURN = """
rc:
  description: Status code after run php-shell (could be changed using `exit(x)`)
  returned: always
  type: int
  sample:
    - 0
stdout:
  description:
    - What the code printed, without the shell's echo of each line of the code.
    - When PHP cannot parse the code, the whole output of the php-shell, with the error.
  returned: always
  type: str
  sample: |
      pfsense.example.com
stderr:
  description: Output on error of the php-shell
  returned: always
  type: str
  sample: ""
changed:
  description:
    - The value of C($ansible_changed) when the code ends, C(true) unless the code sets it to C(false).
    - C(true) when the code stops early (C(exit), C(return)). The task can override it with C(changed_when).
  returned: success
  type: bool
failed:
  description: rc is not 0 or stderr contains output (you still could overwrite with failed_when)
  returned: failure
  type: bool
"""

import json
import uuid

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


PHP_SHELL_ARGUMENT_SPEC = dict(
    cmd=dict(required=True, type="str")
)

# pfSsh.php echoes each line it reads before running them all: the markers are split in the code, so that only the
# lines printed when the code runs hold them whole.
PHP_SHELL_CODE = """$ansible_changed = true;
echo "\\n" . "{marker[0]}" . "{marker[1]}" . "\\n";
{cmd}
echo "\\n" . "{marker[0]}" . "{marker[1]}" . json_encode(array("changed" => (bool) $ansible_changed)) . "\\n";"""


class PFSensePHPShellModule(PFSenseModuleBase):
    """ module run php code on pfsense """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return PHP_SHELL_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSensePHPShellModule, self).__init__(module, pfsense)
        self.name = "pfsense_phpshell"
        self.result["changed"] = True

    ##############################
    # run
    #
    def run(self, params):
        marker = uuid.uuid4().hex
        marker = ("ansible_" + marker[:16], marker[16:])
        (rc, stdout, stderr) = self.pfsense.phpshell(PHP_SHELL_CODE.format(marker=marker, cmd=params["cmd"]))
        (changed, stdout) = self._parse_output(stdout, "\n" + "".join(marker))
        self.result.update({
            "changed": changed,
            "rc": rc,
            "stdout": stdout,
            "stderr": stderr,
        })

        if int(rc) != 0 or len(stderr) > 0:
            self.module.fail_json(msg="rc is not 0 or stderr contains output (you still could overwrite with failed_when)", **self.result)
        else:
            self.module.exit_json(**self.result)

    @staticmethod
    def _parse_output(stdout, marker):
        """ return the changed flag and what the code printed, between the two markers """
        start = stdout.find(marker + "\n")
        if start < 0:
            # PHP did not run the code: keep the shell's output, with the error
            return (True, stdout)
        output = stdout[start + len(marker) + 1:]
        end = output.rfind(marker + "{")
        if end < 0:
            # The code stopped early (exit, return)
            return (True, output)
        try:
            changed = json.loads(output[end + len(marker):].splitlines()[0])["changed"]
        except (ValueError, KeyError, TypeError):
            changed = True
        return (bool(changed), output[:end])


def main():
    module = AnsibleModule(
        argument_spec=PHP_SHELL_ARGUMENT_SPEC,
        supports_check_mode=False)

    pfmodule = PFSensePHPShellModule(module)
    pfmodule.run(module.params)


if __name__ == "__main__":
    main()
