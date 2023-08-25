#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, genofire <geno+dev@fireorbit.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_phpshell
version_added: 0.7.0
author: Geno (@genofire)
short_description: PHP Shell
description:
  - Run a php shell
options:
  cmd:
    description: PHP Code to run
    required: true
    type: str
"""

EXAMPLES = """
- name: run phpshell with code pfSense config.xml
  pfsense_phpshell:
    cmd: |
      require_once("filter.inc");
      require_once("squid.inc");
      squid_resync("yes");
"""

RETURN = """
rc:
  description: Status code after run php-shell (could be changed using `exit(x)`)
  returned: always
  type: int
  sample:
    - 0
stdout:
  description: Output of the php-shell (include your code)
  returned: always
  type: str
  sample: |
      pfSense shell: global $debug;
      pfSense shell: $debug = 1;
      pfSense shell: require_once("filter.inc");
      pfSense shell: require_once("squid.inc");
      pfSense shell: squid_resync("yes");
      pfSense shell:
      pfSense shell: exec
      pfSense shell: exit
stderr:
  description: Output on error of the php-shell
  returned: always
  type: str
  sample: ""
changed:
  description: It returns always true (you could overwrite with changed_when)
  returned: always
  type: bool
failed:
  description: rc is not 0 or stderr contains output (you still could overwrite with failed_when)
  returned: failure
  type: bool
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


PHP_SHELL_ARGUMENT_SPEC = dict(
    cmd=dict(required=True, type='str')
)


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
        self.result['changed'] = True

    ##############################
    # run
    #
    def run(self, params):
        (rc, stdout, stderr) = self.pfsense.phpshell(params['cmd'])
        self.result.update({
            'rc': rc,
            'stdout': stdout,
            'stderr': stderr,
        })

        if int(rc) != 0 or len(stderr) > 0:
            self.module.fail_json(msg='rc is not 0 or stderr contains output (you still could overwrite with failed_when)')
        else:
            self.module.exit_json(**self.result)


def main():
    module = AnsibleModule(
        argument_spec=PHP_SHELL_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSensePHPShellModule(module)
    pfmodule.run(module.params)


if __name__ == '__main__':
    main()
