#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_shellcmd

short_description: Manage pfSense shellcmds

version_added: "0.7.0"

description:
  - Manage pfSense shellcmds. This requires the pfSense shellcmd package to be installed.

options:
  description:
    description: The description of the shellcmd.
    required: true
    type: str
  state:
    description: State in which to leave the shellcmd.
    default: present
    choices: ['present', 'absent']
    type: str
  cmd:
    description: The command to run.
    type: str
  cmdtype:
    description: Type of the shell command, defaults to `shellcmd`. There can only be one `afterfilterchangeshellcmd` command.  If there is an existing one, it
      will be replaced.
    choices: ['shellcmd', 'earlyshellcmd', 'afterfilterchangeshellcmd', 'disabled']
    type: str

author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Add myitem shellcmd
  pfsensible.core.pfsense_shellcmd:
    description: myitem
    cmd: echo hi
    cmdtype: shellcmd
    state: present

- name: Remove myitem shellcmd
  pfsensible.core.pfsense_shellcmd:
    description: myitem
    state: absent
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create shellcmd 'myitem'", "update shellcmd 'myitem' set ...", "delete shellcmd 'myitem'"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

# Compact style
SHELLCMD_ARGUMENT_SPEC = dict(
    # Only description should be required here - othewise you cannot remove an item with just 'description'
    # Required arguments for creation should be noted in SHELLCMD_REQUIRED_IF = ['state', 'present', ...] below
    description=dict(required=True, type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    cmd=dict(type='str'),
    cmdtype=dict(type='str', choices=['shellcmd', 'earlyshellcmd', 'afterfilterchangeshellcmd', 'disabled'],),
)

SHELLCMD_REQUIRED_IF = [
    ['state', 'present', ['cmd']],
]

# default values when creating a new shellcmd
SHELLCMD_CREATE_DEFAULT = dict(
    cmdtype='shellcmd',
)

SHELLCMD_PHP_COMMAND_SET = r'''
require_once("shellcmd.inc");
shellcmd_sync_package();
'''


class PFSenseShellcmdModule(PFSenseModuleBase):
    """ module managing pfsense shellcmds """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return SHELLCMD_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseShellcmdModule, self).__init__(module, pfsense, package='shellcmd', root='shellcmdsettings', node='config', key='description',
                                                    update_php=SHELLCMD_PHP_COMMAND_SET, create_default=SHELLCMD_CREATE_DEFAULT)

    ##############################
    # XML processing
    #
    def _find_target(self):
        """ find the XML target_elt """
        # There can be only one 'afterfilterchangeshellcmd' shellcmd
        if self.params['cmdtype'] == 'afterfilterchangeshellcmd':
            result = self.root_elt.findall("{node}[{key}='{value}']".format(node=self.node, key='cmdtype', value='afterfilterchangeshellcmd'))
        else:
            result = self.root_elt.findall("{node}[{key}='{value}']".format(node=self.node, key=self.key, value=self.obj[self.key]))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple {node}s for {key} {value}.'.format(node=self.node, key=self.key, value=self.obj[self.key]))
        else:
            return None


def main():
    module = AnsibleModule(
        argument_spec=SHELLCMD_ARGUMENT_SPEC,
        required_if=SHELLCMD_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseShellcmdModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
