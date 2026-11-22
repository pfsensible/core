# -*- coding: utf-8 -*-

# Copyright: (c) 2018-2024, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import errno
import json
import os
from ansible_collections.pfsensible.core.plugins.module_utils.alias_references import ALIAS_REFERENCE_FIELDS, alias_reference_names
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

ALIAS_ARGUMENT_SPEC = dict(
    name=dict(required=True, type="str"),
    state=dict(default="present", choices=["present", "absent"]),
    type=dict(required=False, choices=["host", "network", "port", "urltable", "urltable_ports"]),
    address=dict(default=None, required=False, type="str"),
    url=dict(default=None, required=False, type="str"),
    descr=dict(default=None, required=False, type="str"),
    detail=dict(default=None, required=False, type="str"),
    updatefreq=dict(default=None, required=False, type="int"),
)

ALIAS_MUTUALLY_EXCLUSIVE = [
    ("address", "url"),
]

ALIAS_REQUIRED_IF = [
    ["state", "present", ["type"]],
    ["type", "host", ["address"]],
    ["type", "network", ["address"]],
    ["type", "port", ["address"]],
    ["type", "urltable", ["updatefreq"]],
    ["type", "urltable_ports", ["updatefreq"]],
    # When "address" deprecation period is over
    # ["type", "urltable", ["updatefreq", "url"]],
    # ["type", "urltable_ports", ["updatefreq", "url"]],
]

ALIAS_MAP_PARAM_IF = [
    ["type", "urltable", ("address", "url")],
    ["type", "urltable_ports", ("address", "url")],
]

ALIAS_CREATE_DEFAULT = dict(
    descr="",
    detail="",
)

ALIAS_PHP_COMMAND_SET = """
require_once("filter.inc");
alias_make_table();
if (filter_configure() == 0) { clear_subsystem_dirty('aliases'); }
"""


class PFSenseAliasModule(PFSenseModuleBase):
    """ module managing pfsense aliases """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return ALIAS_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseAliasModule, self).__init__(module, pfsense, root="aliases", node="alias", key="name", update_php=ALIAS_PHP_COMMAND_SET,
                                                 map_param_if=ALIAS_MAP_PARAM_IF, create_default=ALIAS_CREATE_DEFAULT)
        # Override for use with aggregate
        self.argument_spec = ALIAS_ARGUMENT_SPEC
        self._urltable_updates = {}
        self._removed_aliases = set()

    ##############################
    # params processing
    #
    def _params_to_obj(self, obj=None):
        obj = super(PFSenseAliasModule, self)._params_to_obj(obj)
        name = self.params["name"]
        if self.params["state"] == "absent":
            self._urltable_updates.pop(name, None)
        elif self.params["type"] in ("urltable", "urltable_ports"):
            # saveAlias() stores the URL in BOTH fields. alias_make_table()
            # registers aliases from 'address', even for URL-table aliases.
            obj["address"] = obj["url"]
            previous = self.pfsense.find_alias(name)
            force = previous is None or previous.findtext("url") != obj["url"]
            self._urltable_updates[name] = self._urltable_updates.get(name, False) or force
        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        # check name
        self.pfsense.check_name(params["name"], "alias")

        if params["state"] == "present":
            if params["type"] in ("urltable", "urltable_ports") and not (params["url"] or params["address"]):
                self.module.fail_json(msg="url (or deprecated address) is required for URL table aliases")
            # the GUI does not allow to create 2 aliases with same name and differents types
            alias_elt = self.pfsense.find_alias(params["name"])
            if alias_elt is not None:
                if params["type"] not in ["host", "network"] or alias_elt.find("type").text not in ["host", "network"]:
                    if params["type"] != alias_elt.find("type").text:
                        self.module.fail_json(msg="An alias with this name and a different type already exists: \'{0}\'".format(params["name"]))

            # Aliases cannot have the same name as an interface description
            if self.pfsense.get_interface_by_display_name(params["name"]) is not None:
                self.module.fail_json(msg="An interface description with this name already exists: \'{0}\'".format(params["name"]))

            # updatefreq is for urltable only
            if params["updatefreq"] is not None and params["type"] != "urltable" and params["type"] != "urltable_ports":
                self.module.fail_json(msg="updatefreq is only valid with type urltable or urltable_ports")

            details = params["detail"].split("||") if params["detail"] is not None else []
            if params["address"] is not None:
                # check details count
                addresses = params["address"].split(" ")
                if len(details) > len(addresses):
                    self.module.fail_json(msg="Too many details in relation to addresses")

                # warn if address is used with urltable to urltable_ports
                if params["type"] in ["urltable", "urltable_ports"]:
                    self.module.warn('Use of "address" with {type} is depracated, please use "url" instead'.format(type=params["type"]))

            # pfSense GUI rule
            for detail in details:
                if detail.startswith("|") or detail.endswith("|"):
                    self.module.fail_json(msg="Vertical bars (|) at start or end of descriptions not allowed")

    def _remove_target_elt(self):
        super(PFSenseAliasModule, self)._remove_target_elt()
        self._removed_aliases.add(self.params["name"])

    def validate_removals(self):
        """Reject removals that would leave references in the staged config."""
        if not self._removed_aliases:
            return
        removed = self._removed_aliases.difference(alias.findtext("name") for alias in self.root_elt)
        if not removed:
            return

        for section, fields in ALIAS_REFERENCE_FIELDS.items():
            for index, entry in enumerate(self.pfsense.root.iterfind(section), start=1):
                for field in fields:
                    value = entry.findtext(field, "")
                    for name in alias_reference_names(section, field, value):
                        if name in removed:
                            label = entry.findtext("descr") or entry.findtext("description") or entry.findtext("name") or str(index)
                            self.module.fail_json(msg=f"Alias '{name}' is in use by {section} '{label}' ({field}).")

    def commit_changes(self):
        self.validate_removals()
        super(PFSenseAliasModule, self).commit_changes()

    def _run_post(self):
        if self.params["state"] == "absent" or self.params["type"] not in ("urltable", "urltable_ports"):
            return
        # Repair runtime state even when the XML already matches. An empty file
        # is not resolvable by alias_expand(), so merely touching it is unsafe.
        path = "/var/db/aliastables/{0}.txt".format(self.params["name"])
        try:
            missing = os.path.getsize(path) == 0
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise
            missing = True
        if missing:
            self.result["changed"] = True
            if not self.change_descr:
                self.change_descr = "ansible alias initialized URL table {0}".format(self.params["name"])

    def initialize_url_tables(self):
        """Download selected URL tables and refresh existing PF address tables."""
        if not self._urltable_updates:
            return
        # Names are validated alias names; URLs are read from committed config
        # rather than embedded in PHP or returned in failure output.
        requests = json.dumps(self._urltable_updates)
        command = """require_once("pfsense-utils.inc");
$requests = json_decode('%s', true);
$failed = array();
$updated = array();
foreach (config_get_path('aliases/alias', array()) as $alias) {
    $name = $alias['name'];
    if (!array_key_exists($name, $requests)) {
        continue;
    }
    $status = process_alias_urltable($name, $alias['type'], $alias['url'],
        $alias['updatefreq'], $requests[$name]);
    $path = '/var/db/aliastables/' . $name . '.txt';
    clearstatcache(true, $path);
    if ($status === false || !is_readable($path) || trim(file_get_contents($path)) === '') {
        $failed[] = $name;
    } elseif ($alias['type'] === 'urltable' && ($status === true || $status === 1)) {
        $updated[] = $name;
    }
    unset($requests[$name]);
}
$failed = array_merge($failed, array_keys($requests));
echo json_encode(array('failed_aliases' => $failed, 'updated_aliases' => $updated));
""" % requests
        result = self.pfsense.php(command)
        if result["failed_aliases"]:
            self.module.fail_json(
                msg="URL table initialization failed or returned no usable entries; filter reload was not attempted",
                failed_aliases=result["failed_aliases"], changed=True)
        self._refresh_url_tables(result.get("updated_aliases", []))

    def _refresh_url_tables(self, names):
        """Mirror rc.update_urltables: refresh existing address tables explicitly."""
        # A filter reload can be skipped when only a referenced table file changed.
        if not names:
            return
        code, stdout, unused_stderr = self.module.run_command(["/sbin/pfctl", "-s", "Tables"])
        if code != 0:
            self.module.fail_json(msg="Unable to inspect PF tables after URL table download; filter reload was not attempted",
                                  failed_aliases=names, changed=True)
        existing = set(line.strip() for line in stdout.splitlines())
        failed = []
        for name in names:
            # A new/unreferenced alias may not have a PF table yet. The normal
            # filter reload creates it. Port aliases use macros, not PF tables.
            if name not in existing:
                continue
            path = "/var/db/aliastables/{0}.txt".format(name)
            code, unused_stdout, unused_stderr = self.module.run_command(
                ["/sbin/pfctl", "-t", name, "-T", "replace", "-f", path])
            if code != 0:
                failed.append(name)
        if failed:
            self.module.fail_json(msg="URL table download succeeded, but PF table replacement failed; filter reload was not attempted",
                                  failed_aliases=failed, changed=True)

    def _update(self):
        self.initialize_url_tables()
        return super(PFSenseAliasModule, self)._update()
