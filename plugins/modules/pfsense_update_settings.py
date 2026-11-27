#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Romain Tiennot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_update_settings

short_description: Manage pfSense update settings

version_added: "0.8.0"

description:
  - Manage System > Update > Update Settings, the branch of updates and the dashboard's check, and on pfSense Plus the boot environment
    created before an upgrade. The GitHub synchronization settings of the page are left as they are.
  - Omitted options preserve existing settings.

options:
  branch:
    description:
      - Branch of updates, as the page lists them (the repository's name, stored in C(pkg_repo_conf_path)). The module checks it
        against the repositories of the firewall.
      - For example C(26.07.2), the name of the stable branch on pfSense Plus 26.07.2.
      - As the page does, a change switches the package repository.
    type: str
  disablecheck:
    description: Disable the dashboard's check for updates.
    type: bool
  disableautobe:
    description:
      - Do not create a boot environment automatically before an upgrade, which leaves nothing to go back to after a failed one.
      - pfSense Plus only.
    type: bool

author: Romain Tiennot (@RomainTie)
"""

EXAMPLES = r"""
- name: Check for updates on the dashboard, and keep a boot environment before each upgrade
  pfsensible.core.pfsense_update_settings:
    disablecheck: false
    disableautobe: false

- name: Follow the 26.07.2 branch
  pfsensible.core.pfsense_update_settings:
    branch: "26.07.2"
"""

RETURN = r"""
commands:
    description: Pseudo-CLI commands describing configuration changes.
    returned: always
    type: list
    elements: str
    sample: ["update update_settings firmware set disableautobe=False"]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

UPDATE_SETTINGS_ARGUMENT_SPEC = dict(
    branch=dict(type="str"),
    disablecheck=dict(type="bool"),
    disableautobe=dict(type="bool"),
)

# The checkboxes, stored by presence in <system><firmware>
FIRMWARE_FLAGS = ["disablecheck", "disableautobe"]

# The repositories the page lists
LIST_REPOS_PHP_COMMAND = """
require_once("pkg-utils.inc");
echo json_encode(array_values(array_map(function ($repo) { return $repo["name"]; }, pkg_list_repos())));
"""

# What the page does when the branch changes
SWITCH_REPO_PHP_COMMAND = """
require_once("pkg-utils.inc");
pkg_switch_repo();
"""


class PFSenseUpdateSettingsModule(PFSenseModuleConfigBase):
    """ module managing pfSense update settings """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return UPDATE_SETTINGS_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseUpdateSettingsModule, self).__init__(module, pfsense, name="pfsense_update_settings", root="pfsense", node="system")
        self.params_to_delete = list()

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do the checks of the web GUI """
        branch = self.params.get("branch")
        if branch is not None:
            repos = self.pfsense.php(LIST_REPOS_PHP_COMMAND)
            if branch not in repos:
                self.module.fail_json(msg="branch {0} is not one of the firewall's: {1}".format(branch, ", ".join(repos)))

    def _params_to_obj(self):
        """ return a dict from module params """
        system = self.pfsense.get_element(self.node, root_elt=self.root_elt)
        obj = self.pfsense.element_to_dict(system) if system is not None else dict()
        if self.params.get("branch") is not None:
            obj["pkg_repo_conf_path"] = self.params["branch"]

        firmware = obj.get("firmware") if isinstance(obj.get("firmware"), dict) else dict()
        for flag in FIRMWARE_FLAGS:
            if self.params.get(flag) is True:
                firmware[flag] = ""
            elif self.params.get(flag) is False:
                firmware.pop(flag, None)
        if firmware:
            obj["firmware"] = firmware
        elif "firmware" in obj:
            # As the page does, no empty section is left
            del obj["firmware"]
            self.params_to_delete.append("firmware")
        return obj

    def _get_params_to_remove(self):
        """ returns the list of params to remove """
        return self.params_to_delete

    def run(self, params):
        if any(value is not None for value in params.values()):
            super(PFSenseUpdateSettingsModule, self).run(params)

    def _run_post(self):
        # The diff of the whole system section would show the users, their password hashes and other secrets: keep the settings
        # of the page only
        for key in ("before", "after"):
            snapshot = self.diff.get(key) or {}
            self.diff[key] = dict((field, snapshot[field]) for field in ("pkg_repo_conf_path", "firmware") if field in snapshot)

    ##############################
    # run
    #
    def _update(self):
        """ switch the package repository when the branch changed, as the page does """
        if self.obj.get("pkg_repo_conf_path") != self.diff["before"].get("pkg_repo_conf_path"):
            return self.pfsense.phpshell(SWITCH_REPO_PHP_COMMAND)
        return ("", "", "")

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "firmware"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters """
        after = self.obj
        before = before if before is not None else dict()
        values = []
        if after.get("pkg_repo_conf_path") != before.get("pkg_repo_conf_path"):
            values.append("branch='{0}'".format(after.get("pkg_repo_conf_path")))
        for flag in FIRMWARE_FLAGS:
            flag_after = flag in (after.get("firmware") or {})
            flag_before = isinstance(before.get("firmware"), dict) and flag in before["firmware"]
            if flag_after != flag_before:
                values.append("{0}={1}".format(flag, flag_after))
        return ", ".join(values)


def main():
    module = AnsibleModule(
        argument_spec=UPDATE_SETTINGS_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseUpdateSettingsModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
