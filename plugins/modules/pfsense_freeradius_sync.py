#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Romain Tiennot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_freeradius_sync

short_description: Manage the XMLRPC sync settings of the FreeRADIUS package

version_added: "0.8.0"

description:
  - Manage Services > FreeRADIUS > XMLRPC Sync, which copies the FreeRADIUS settings to other firewalls.
  - The freeradius3 package must be installed.
  - Omitted options preserve existing settings.
  - As the web GUI does, a change runs the package's sync, which in V(manual) mode copies the settings to the hosts right away.
    It can take up to a few times O(timeout) per host, and its errors only go to the system log.

options:
  mode:
    description:
      - V(auto) adds the FreeRADIUS settings to the High Availability configuration sync, to the peer and with the account set
        in System > High Availability. That sync must be configured, with at least one item to synchronize.
      - V(manual) syncs to the hosts given by O(targets).
      - V(disabled) does not sync.
    type: str
    choices: [auto, manual, disabled]
  timeout:
    description: Timeout of the sync, in seconds. Used only when O(mode=manual).
    type: int
  targets:
    description:
      - Hosts to sync to when O(mode=manual). The list replaces the configured hosts.
      - An empty list removes them.
    type: list
    elements: dict
    suboptions:
      address:
        description: IP address or hostname of the host.
        type: str
        required: true
      port:
        description: Port of the host's web GUI.
        type: int
        default: 443
      protocol:
        description: Protocol of the host's web GUI.
        type: str
        choices: [http, https]
        default: https
      username:
        description: User name on the host.
        type: str
        default: admin
      password:
        description: Password of O(targets[].username) on the host.
        type: str
        required: true
      enabled:
        description: Sync to this host.
        type: bool
        default: true

author: Romain Tiennot (@RomainTie)
"""

EXAMPLES = r"""
- name: Sync FreeRADIUS to the High Availability peer
  pfsensible.core.pfsense_freeradius_sync:
    mode: auto
    targets: []

- name: Sync FreeRADIUS to another firewall
  pfsensible.core.pfsense_freeradius_sync:
    mode: manual
    targets:
      - address: 192.168.1.2
        password: "{{ vault_sync_password }}"
"""

RETURN = r"""
commands:
    description: Pseudo-CLI commands describing configuration changes.
    returned: always
    type: list
    elements: str
    sample: ["update freeradius_sync xmlrpc set mode='auto', targets=''"]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

FREERADIUS_SYNC_ARGUMENT_SPEC = dict(
    mode=dict(type="str", choices=["auto", "manual", "disabled"]),
    timeout=dict(type="int"),
    targets=dict(type="list", elements="dict", options=dict(
        address=dict(type="str", required=True),
        port=dict(type="int", default=443),
        protocol=dict(type="str", choices=["http", "https"], default="https"),
        username=dict(type="str", default="admin"),
        password=dict(type="str", required=True, no_log=True),
        enabled=dict(type="bool", default=True),
    )),
)

# What the package runs when its XMLRPC Sync page is saved
FREERADIUS_SYNC_PHP_COMMAND = """
require_once("/usr/local/pkg/freeradius.inc");
freeradius_sync_on_changes();
"""

REDACTED = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"


def rows_of(obj):
    """ the targets of a settings dict, as a list """
    rows = obj.get("row", [])
    if isinstance(rows, dict):
        return [rows]
    if isinstance(rows, list):
        return rows
    return []


def targets_summary(rows):
    """ the targets without their passwords, for the commands """
    summary = []
    for row in rows:
        target = "{0}://{1}:{2}".format(row.get("varsyncprotocol", ""), row.get("varsyncipaddress", ""), row.get("varsyncport", ""))
        if not row.get("varsyncdestinenable"):
            target += " (disabled)"
        summary.append(target)
    return " ".join(summary)


class PFSenseFreeRADIUSSyncModule(PFSenseModuleConfigBase):
    """ module managing the XMLRPC sync settings of the FreeRADIUS package """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return FREERADIUS_SYNC_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseFreeRADIUSSyncModule, self).__init__(
            module, pfsense, package="freeradius3", name="pfsense_freeradius_sync", root="freeradiussync", node="config", create_root=True,
            update_php=FREERADIUS_SYNC_PHP_COMMAND,
        )

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params
        timeout = params.get("timeout")
        if timeout is not None and (isinstance(timeout, bool) or timeout < 1):
            self.module.fail_json(msg="timeout must be a positive number of seconds")

        for target in params.get("targets") or []:
            if not target["address"]:
                self.module.fail_json(msg="targets must have an address")
            if isinstance(target["port"], bool) or not 1 <= target["port"] <= 65535:
                self.module.fail_json(msg="port of target {0} must be between 1 and 65535".format(target["address"]))

        config = self.pfsense.get_element(self.node, root_elt=self.root_elt)
        mode = params.get("mode")
        if mode is None and config is not None:
            mode = config.findtext("varsyncenablexmlrpc")
        if params.get("targets") is not None:
            targets = params["targets"]
        else:
            targets = rows_of(self.pfsense.element_to_dict(config)) if config is not None else []
        if mode == "manual" and not targets:
            self.module.fail_json(msg="targets are required when mode is manual")

    def _params_to_obj(self):
        """ return a dict from module params """
        config = self.pfsense.get_element(self.node, root_elt=self.root_elt)
        obj = self.pfsense.element_to_dict(config) if config is not None else dict()
        params = self.params
        if params.get("mode") is not None:
            obj["varsyncenablexmlrpc"] = params["mode"]
        if params.get("timeout") is not None:
            obj["varsynctimeout"] = str(params["timeout"])
        if params.get("targets") is not None:
            rows = []
            for target in params["targets"]:
                row = dict()
                # A checkbox of the package's form: "ON" when ticked, absent otherwise
                if target["enabled"]:
                    row["varsyncdestinenable"] = "ON"
                row["varsyncprotocol"] = target["protocol"]
                row["varsyncipaddress"] = target["address"]
                row["varsyncport"] = str(target["port"])
                row["varsyncusername"] = target["username"]
                row["varsyncpassword"] = target["password"]
                rows.append(row)
            obj["row"] = rows
        return obj

    def run(self, params):
        if any(value is not None for value in params.values()):
            super(PFSenseFreeRADIUSSyncModule, self).run(params)

    def _run_post(self):
        # The diff holds the stored targets: hide their passwords
        for snapshot in self.diff.values():
            rows = snapshot.get("row")
            for row in [rows] if isinstance(rows, dict) else rows if isinstance(rows, list) else []:
                if row.get("varsyncpassword"):
                    row["varsyncpassword"] = REDACTED

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "xmlrpc"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters """
        values = ""
        if before is None:
            values += self.format_cli_field(self.obj, "varsyncenablexmlrpc", fname="mode")
            values += self.format_cli_field(self.obj, "varsynctimeout", fname="timeout")
            if "row" in self.obj:
                values += self.format_cli_field(dict(targets=targets_summary(rows_of(self.obj))), "targets")
        else:
            after = self.diff["after"]
            values += self.format_updated_cli_field(after, before, "varsyncenablexmlrpc", fname="mode", add_comma=(values))
            values += self.format_updated_cli_field(after, before, "varsynctimeout", fname="timeout", add_comma=(values))
            if rows_of(after) != rows_of(before):
                summary = targets_summary(rows_of(after))
                if summary == targets_summary(rows_of(before)):
                    summary += " (updated)"
                values += self.format_cli_field(dict(targets=summary), "targets", add_comma=(values))
        return values


def main():
    module = AnsibleModule(
        argument_spec=FREERADIUS_SYNC_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseFreeRADIUSSyncModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
