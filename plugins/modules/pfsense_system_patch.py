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
module: pfsense_system_patch
version_added: 0.6.0
author: Geno (@genofire)
short_description: System Patch
description:
  - Manage System Patch
notes:
options:
  id:
    description: ID of Patch - for update / delete the correct
    type: str
    required: True
  description:
    description: The name of the patch in the "System Patch" menu.
    type: str
    required: False
  content:
    description: The contents of the patch.
    type: str
    required: False
  src:
    description: Path to a patch file.
    type: path
    required: False
  location:
    description: Location.
    type: str
    required: False
    default: ""
  pathstrip:
    description: The number of levels to strip from the front of the path in the patch header.
    type: int
    required: False
    default: 2
  basedir:
    description: |
      Enter the base directory for the patch, default is /.
      Patches from github are all based in /.
      Custom patches may need a full path here such as /usr/local/www/.
    type: str
    required: False
    default: "/"
  ignore_whitespace:
    description: Ignore whitespace in the patch.
    type: bool
    required: False
    default: true
  auto_apply:
    description: Apply the patch automatically when possible, useful for patches to survive after updates.
    type: bool
    required: False
    default: false
  state:
    description: State in which to leave the interface group.
    choices: [ "present", "absent" ]
    default: present
    type: str
  run:
    description: State in which to leave the interface group.
    choices: [ "no", "apply", "revert" ]
    default: "no"
    type: str
"""

EXAMPLES = """
- name: Try Systempatch
  pfsense_system_patch:
    id: "3f60a103a613"
    description: "Hello Welt Patch"
    content: >
       --- b/tmp/test.txt
       +++ a/tmp/test.txt
       @@ -0,0 +1 @@
       +Hello Welt
    location: ""
    pathstrip: 1
    basedir: "/"
    ignore_whitespace: true
    auto_apply: true
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.system_patch import (
    PFSenseSystemPatchModule,
    SYSTEMPATCH_ARGUMENT_SPEC,
    SYSTEMPATCH_MUTUALLY_EXCLUSIVE,
    SYSTEMPATCH_REQUIRED_IF
)


def main():
    module = AnsibleModule(
        argument_spec=SYSTEMPATCH_ARGUMENT_SPEC,
        mutually_exclusive=SYSTEMPATCH_MUTUALLY_EXCLUSIVE,
        required_if=SYSTEMPATCH_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseSystemPatchModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
