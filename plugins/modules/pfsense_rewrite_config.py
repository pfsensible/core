#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_rewrite_config
version_added: 0.5.3
author: Orion Poplawski (@opoplawski)
short_description: Rewrite pfSense config.xml
description:
  - Rewrites pfSense's config.xml using native tools to reproduce formatting.
notes:
"""

EXAMPLES = """
- name: Rewrite pfSense config.xml
  pfsense_rewrite_config:
"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


REWRITE_CONFIG_ARGUMENT_SPEC = dict()


class PFSenseRewriteConfigModule(PFSenseModuleBase):
    """ module managing pfsense routes """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return REWRITE_CONFIG_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseRewriteConfigModule, self).__init__(module, pfsense)
        self.name = "pfsense_rewrite_config"
        self.result['changed'] = True

    ##############################
    # run
    #
    def commit_changes(self):
        """ apply changes and exit module """
        self.result['stdout'] = ''
        self.result['stderr'] = ''
        if self.result['changed'] and not self.module.check_mode:
            (dummy, self.result['stdout'], self.result['stderr']) = self._update()

        self.module.exit_json(**self.result)

    def _update(self):
        """ make the target pfsense rewrite the config.xml file """

        cmd = '''
parse_config(true);
write_config('pfsense_rewrite_config');'''

        return self.pfsense.phpshell(cmd)


def main():
    module = AnsibleModule(
        argument_spec=REWRITE_CONFIG_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseRewriteConfigModule(module)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
