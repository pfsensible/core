#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, genofire <geno+dev@fireorbit.de>
# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = """
---
module: pfsense_system_patch
version_added: "0.8.0"
author: Geno (@genofire)
short_description: Manage custom pfSense system patches
description:
  - Manage custom entries in the pfSense System Patches package.
  - A task can also apply or revert a patch on the pfSense filesystem.
requirements:
  - The pfSense System Patches package must be installed.
notes:
  - Specify at least one of I(descr) and I(uniqid).
  - New entries need patch data from I(content), I(src), or I(location).
  - I(content) and I(src) are mutually exclusive. Either can be used with I(location) to provide the contents directly.
  - When I(location) supplies the patch, the module downloads it from the managed pfSense device if the location changes or the entry has no saved contents.
    This download also happens in check mode. Subsequent runs reuse the saved contents for the same location.
options:
  descr:
    description:
      - The patch description in the System > Patches menu. Required when creating an entry.
      - Identifies the entry when I(uniqid) is omitted. When I(uniqid) identifies an existing entry, use I(descr) to change its description.
    type: str
  uniqid:
    description:
      - The patch ID in the System > Patches menu.
      - When supplied, identifies the entry for every operation and is saved as its ID on creation.
      - When omitted, the module identifies the entry by I(descr) and generates an ID on creation.
      - Must be nonempty and cannot contain slashes or control characters.
    type: str
  content:
    description: The contents of a unified diff. Use a literal YAML block to preserve line breaks.
    type: str
  src:
    description:
      - Path to a UTF-8 patch file on the Ansible controller. Relative paths use Ansible's standard file search paths.
      - Set C(remote_src=true) to read the file directly on the managed pfSense device.
    type: path
  remote_src:
    description: Whether I(src) names a file on the managed pfSense device.
    type: bool
    default: false
  location:
    description:
      - HTTP or HTTPS URL for a patch, or a lowercase Git commit ID from the pfSense CE repository.
      - Use an empty string to clear the source location and keep the saved contents.
    type: str
  pathstrip:
    description:
      - Number of leading path components to strip from patch headers, from 0 to 20.
      - Defaults to C(2) for new entries.
    type: int
  basedir:
    description:
      - Existing absolute directory on the managed pfSense device relative to which the patch is applied.
      - Defaults to C(/) for new entries.
    type: str
  ignore_whitespace:
    description:
      - Ignore whitespace differences when matching patch context.
      - Defaults to C(true) for new entries.
    type: bool
  auto_apply:
    description:
      - Register the patch for automatic application by the package at boot.
      - Defaults to C(false) for new entries.
    type: bool
  state:
    description: Whether the patch entry should be present or absent.
    choices: [present, absent]
    default: present
    type: str
  run:
    description:
      - Choose whether to leave patched files alone, apply the patch, or revert the patch.
      - With C(state=absent), use C(revert) to revert the saved patch before deleting its entry.
      - A reverted entry with I(auto_apply) enabled is still eligible for automatic application at boot.
      - The module skips the runtime action when the opposite dry run succeeds, including when both directions succeed.
    choices: ["no", apply, revert]
    default: "no"
    type: str
"""

EXAMPLES = """
- name: Save and apply a patch that updates a local banner
  pfsensible.core.pfsense_system_patch:
    descr: Update the local banner
    basedir: /usr/local/etc
    pathstrip: 0
    content: |
      --- local-banner.txt
      +++ local-banner.txt
      @@ -1 +1 @@
      -Welcome
      +Welcome to the lab
    run: apply

- name: Revert the banner patch and remove its entry
  pfsensible.core.pfsense_system_patch:
    descr: Update the local banner
    state: absent
    run: revert

- name: Save a patch from the controller with a fixed ID
  pfsensible.core.pfsense_system_patch:
    uniqid: lab-banner
    descr: Update the local banner
    src: banner.patch

- name: Update that entry from a file on pfSense
  pfsensible.core.pfsense_system_patch:
    uniqid: lab-banner
    src: /tmp/banner.patch
    remote_src: true
"""

RETURN = """
commands:
  description: The patch configuration and runtime actions reported by the module.
  returned: always
  type: list
  elements: str
  sample: ["apply system_patch 'Update the local banner'"]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.system_patch import (
    PFSenseSystemPatchModule,
    SYSTEMPATCH_ARGUMENT_SPEC,
    SYSTEMPATCH_MUTUALLY_EXCLUSIVE,
)


def main():
    module = AnsibleModule(
        argument_spec=SYSTEMPATCH_ARGUMENT_SPEC,
        mutually_exclusive=SYSTEMPATCH_MUTUALLY_EXCLUSIVE,
        required_one_of=[("descr", "uniqid")],
        supports_check_mode=True,
    )

    pfmodule = PFSenseSystemPatchModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
