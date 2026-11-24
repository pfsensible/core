#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Romain Tiennot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_autoconfigbackup

short_description: Manage pfSense AutoConfigBackup settings

version_added: "0.8.0"

description:
  - Manage the settings of Services > Auto Config Backup, which keeps encrypted copies of the configuration on Netgate's servers.
  - Omitted options preserve existing settings.
  - As the web GUI does, saving the settings installs or removes the cron jobs and creates a configuration revision, and enabling
    the backups creates a random device key when none is stored.

options:
  enable:
    description:
      - Enable automatic configuration backups.
      - An encryption password must be stored or given with O(encryption_password).
    type: bool
  frequency:
    description:
      - V(every) backs up after each configuration change saved by pfSense itself. Changes made with this collection do not
        trigger it.
      - V(cron) backs up on the schedule given by O(minute), O(hour), O(day), O(month) and O(dow), when the configuration changed.
    type: str
    choices: [every, cron]
  minute:
    description:
      - Minute of the scheduled backups, as in a cron entry (digits and C(*), C(/), C(-), C(,)).
      - As in the web GUI, V(0) is not used. When no minute is given or stored, a random one from 1 to 59 is stored.
    type: str
  hour:
    description:
      - Hour of the scheduled backups, a number or C(*).
      - When none is given or stored, every hour.
    type: str
  day:
    description: Day of the month of the scheduled backups, a number or C(*).
    type: str
  month:
    description: Month of the scheduled backups, a number or C(*).
    type: str
  dow:
    description: Day of the week of the scheduled backups, a number or C(*).
    type: str
  numman:
    description: Number of manual backups to keep, from 0 to 50.
    type: int
  reverse:
    description: List the backups newest first.
    type: bool
  hint:
    description: Hint or identifier shown with the backups, up to 255 characters.
    type: str
  encryption_password:
    description:
      - Password that encrypts the backups, at least 8 characters.
      - It is compared with the stored password and written when they differ. Backups already uploaded keep their password.
    type: str

author: Romain Tiennot (@RomainTie)
"""

EXAMPLES = r"""
- name: Back up the configuration every day at 00:44
  pfsensible.core.pfsense_autoconfigbackup:
    enable: true
    frequency: cron
    minute: "44"
    hour: "0"
    day: "*"
    month: "*"
    dow: "*"
    encryption_password: "{{ vault_acb_password }}"

- name: Disable AutoConfigBackup and retain its settings
  pfsensible.core.pfsense_autoconfigbackup:
    enable: false
"""

RETURN = r"""
commands:
    description: Pseudo-CLI commands describing configuration changes.
    returned: always
    type: list
    elements: str
    sample: ["update autoconfigbackup acb set enable=True, frequency='cron'"]
"""

import random
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

AUTOCONFIGBACKUP_ARGUMENT_SPEC = dict(
    enable=dict(type="bool"),
    frequency=dict(type="str", choices=["every", "cron"]),
    minute=dict(type="str"),
    hour=dict(type="str"),
    day=dict(type="str"),
    month=dict(type="str"),
    dow=dict(type="str"),
    numman=dict(type="int"),
    reverse=dict(type="bool"),
    hint=dict(type="str"),
    encryption_password=dict(type="str", no_log=True),
)

# What setup_ACB() (/etc/inc/acb.inc) and the settings page do once the settings are stored.
# $new_key is set by the module: true when the backups are being enabled.
AUTOCONFIGBACKUP_PHP_COMMAND = """
require_once("services.inc");
require_once("acb.inc");
if ($new_key && function_exists("acb_generate_device_key") && function_exists("is_valid_acb_device_key") &&
    !is_valid_acb_device_key(config_get_path("system/acb/device_key", ""))) {
    $key = acb_generate_device_key();
    if (is_valid_acb_device_key($key)) {
        config_set_path("system/acb/device_key", $key);
    }
}
$acb = config_get_path("system/acb", []);
install_cron_job("/usr/bin/nice -n20 /usr/local/bin/php /usr/local/sbin/execacb.php",
    ($acb["frequency"] ?? "") == "cron",
    $acb["minute"] ?? "0",
    is_numeric($acb["hour"] ?? "") ? $acb["hour"] : "*",
    is_numeric($acb["day"] ?? "") ? $acb["day"] : "*",
    is_numeric($acb["month"] ?? "") ? $acb["month"] : "*",
    is_numeric($acb["dow"] ?? "") ? $acb["dow"] : "*");
if (file_exists("/usr/local/sbin/acbupload.php")) {
    install_cron_job("/usr/bin/nice -n20 /usr/local/bin/php /usr/local/sbin/acbupload.php", ($acb["enable"] ?? "") == "yes", "*");
}
write_config("AutoConfigBackup settings updated");
"""

REDACTED = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"


def is_secret(field):
    """ the stored passwords (including the gold_* ones of the former package) and the device key """
    return "password" in field or field == "device_key"


class PFSenseAutoConfigBackupModule(PFSenseModuleConfigBase):
    """ module managing pfSense AutoConfigBackup settings """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return AUTOCONFIGBACKUP_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseAutoConfigBackupModule, self).__init__(
            module, pfsense, name="pfsense_autoconfigbackup", root="system", node="acb", create_root=True,
            bool_values=dict(enable=("", "yes"), reverse=("", "yes")),
        )
        self.new_key = False

    ##############################
    # params processing
    #
    def _stored(self, field):
        acb = self.root_elt.find(self.node)
        return acb.findtext(field) if acb is not None else None

    def _current(self, field):
        if self.params.get(field) is not None:
            return self.params[field]
        return self._stored(field)

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params.get("minute") is not None:
            if not re.fullmatch(r"[0-9*/,-]+", params["minute"]):
                self.module.fail_json(msg="minute may only contain digits and the characters * / - ,")
            if re.fullmatch(r"0+", params["minute"]):
                self.module.fail_json(msg="minute 0 is not used by pfSense: give 1 to 59, or omit it to get a random one")

        for field in ["hour", "day", "month", "dow"]:
            if params.get(field) is not None and not re.fullmatch(r"[0-9]+|\*", params[field]):
                self.module.fail_json(msg="{0} must be a number or *".format(field))

        numman = params.get("numman")
        if numman is not None and (isinstance(numman, bool) or not 0 <= numman <= 50):
            self.module.fail_json(msg="numman must be between 0 and 50")

        if params.get("hint") is not None and len(params["hint"]) > 255:
            self.module.fail_json(msg="hint must be at most 255 characters")

        if params.get("encryption_password") is not None and len(params["encryption_password"]) < 8:
            self.module.fail_json(msg="encryption_password must be at least 8 characters")

        enabled = params["enable"] if params.get("enable") is not None else self._stored("enable") == "yes"
        if enabled and not self._current("encryption_password"):
            self.module.fail_json(msg="encryption_password is required to enable AutoConfigBackup")

    def _params_to_obj(self):
        """ return a dict from module params """
        obj = super(PFSenseAutoConfigBackupModule, self)._params_to_obj()

        # A false option that is not stored is already false: do not add an empty element for it
        for field in ["enable", "reverse"]:
            if obj.get(field) == "" and self._stored(field) is None:
                del obj[field]

        # As setup_ACB() does, pick a random minute when there is none
        if self._current("frequency") == "cron" and not self._current("minute"):
            obj["minute"] = str(random.randint(1, 59))

        return obj

    def run(self, params):
        if any(value is not None for value in params.values()):
            super(PFSenseAutoConfigBackupModule, self).run(params)

    def _run_post(self):
        # The web GUI creates a random device key when the backups are enabled
        self.new_key = self.diff["before"].get("enable") != "yes" and self.diff["after"].get("enable") == "yes"

        # The diff holds the whole section: hide the stored secrets
        for snapshot in self.diff.values():
            for field in snapshot:
                if is_secret(field) and snapshot[field]:
                    snapshot[field] = REDACTED

    ##############################
    # run
    #
    def _update(self):
        """ install the cron jobs and create the revision, as the web GUI does """
        return self.pfsense.phpshell("$new_key = {0};\n{1}".format("true" if self.new_key else "false", AUTOCONFIGBACKUP_PHP_COMMAND))

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "acb"

    @staticmethod
    def fvalue_bool(value):
        """ enable and reverse are stored as 'yes' when set """
        return "True" if value == "yes" else "False"

    def format_cli_field(self, after, field, *args, **kwargs):
        if is_secret(field) and after.get(field):
            after = dict(after)
            after[field] = REDACTED
        return super(PFSenseAutoConfigBackupModule, self).format_cli_field(after, field, *args, **kwargs)


def main():
    module = AnsibleModule(
        argument_spec=AUTOCONFIGBACKUP_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseAutoConfigBackupModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
