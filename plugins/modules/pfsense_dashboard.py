#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_dashboard

short_description: Manage pfSense dashboard configuration

version_added: "0.8.0"

description:
  - Manage pfSense dashboard configuration.

options:
  sequence:
    description:
      - Dashboard widget order and layout.
      - Each comma-separated entry uses the pfSense format C(widget:column:state:index),
        for example C(system_information:col1:open:0).
    type: str
  options:
    description:
      - Widget-specific settings, keyed by the widget ID used in O(sequence).
      - Widget IDs and setting names are not restricted to built-in widgets, so
        package-provided and version-specific widgets are supported.
      - Setting values may be nested dictionaries or lists; scalar values are
        stored as strings in the pfSense configuration.
    type: dict

author: Orion Poplawski (@opoplawski)
"""

EXAMPLES = r"""
- name: Configure pfSense dashboard
  pfsensible.core.pfsense_dashboard:
    sequence: system_information:col1:open:0,traffic_graphs:col2:open:0,openvpn-0:col2:open:0
    options:
      traffic_graphs:
        filter: wan,lan
      openvpn-0:
        filter: all
"""
RETURN = r"""
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: ["update dashboard set ..."]
"""

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_config_base import PFSenseModuleConfigBase

WIDGET_SEQUENCE_ENTRY = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):col([1-6]):(open|close)(?::([0-9]+))?$")
XML_ELEMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")

DASHBOARD_ARGUMENT_SPEC = dict(
    sequence=dict(type="str"),
    options=dict(type="dict"),
)


class PFSenseDashboardModule(PFSenseModuleConfigBase):
    """module managing pfsense dashboard configuration"""

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """return argument spec"""
        return DASHBOARD_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        arg_route = dict(
            sequence=dict(validate=PFSenseDashboardModule._validate_sequence),
            options=dict(parse=PFSenseDashboardModule._p2o_options, validate=PFSenseDashboardModule._validate_options),
        )
        super(PFSenseDashboardModule, self).__init__(module, pfsense, root="pfsense", node="widgets", bool_style="absent/present", arg_route=arg_route)

    @staticmethod
    def _widget_ids(sequence):
        """Return widget IDs from a pfSense dashboard sequence."""
        widget_ids = set()
        if not sequence:
            return widget_ids

        for entry in sequence.split(","):
            match = WIDGET_SEQUENCE_ENTRY.fullmatch(entry)
            if match is None:
                raise ValueError("Invalid dashboard sequence entry {0!r}; expected widget:col1..col6:open|close[:index]".format(entry))
            widget_ids.add(match.group(1))

        return widget_ids

    @staticmethod
    def _validate_widget_value(value, path):
        """Validate widget settings and prepare values for XML serialization."""
        if isinstance(value, dict):
            normalized = {}
            for key, item in value.items():
                if not isinstance(key, str) or not XML_ELEMENT_NAME.fullmatch(key):
                    raise ValueError("Invalid dashboard widget setting name {0!r} at {1}".format(key, path))
                normalized[key] = PFSenseDashboardModule._validate_widget_value(item, "{0}.{1}".format(path, key))
            return normalized

        if isinstance(value, list):
            return [PFSenseDashboardModule._validate_widget_value(item, "{0}[]".format(path)) for item in value]

        if value is None:
            return ""
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, (str, int, float)):
            return str(value)

        raise ValueError("Invalid value type for dashboard widget setting at {0}".format(path))

    def _get_current_widget_ids(self):
        """Return widget IDs from the existing sequence when no new sequence is given."""
        widgets = self.pfsense.get_element("widgets", root_elt=self.root_elt)
        if widgets is None:
            return set()

        sequence = widgets.findtext("sequence")
        try:
            return self._widget_ids(sequence)
        except ValueError as error:
            self.module.fail_json(msg="The existing dashboard configuration has an invalid sequence: {0}".format(error))

    def _validate_sequence(self, sequence):
        """Validate the requested dashboard sequence and its widget identifiers."""
        self._widget_ids(sequence)

    def _validate_options(self, options):
        """Validate widget IDs and recursively validate their setting values."""
        sequence = self.params.get("sequence")
        if sequence is None:
            widget_ids = self._get_current_widget_ids()
        else:
            widget_ids = self._widget_ids(sequence)

        for widget_id, settings in options.items():
            if not isinstance(widget_id, str) or not XML_ELEMENT_NAME.fullmatch(widget_id):
                raise ValueError("Invalid dashboard widget ID {0!r}".format(widget_id))
            if widget_id not in widget_ids:
                raise ValueError("Dashboard widget {0!r} is not present in the sequence".format(widget_id))
            if not isinstance(settings, dict):
                raise ValueError("Dashboard widget options for {0!r} must be a dictionary".format(widget_id))
            self._validate_widget_value(settings, widget_id)

    def _p2o_options(self, name, params, obj):
        """Parse widget settings into XML-compatible values."""
        for key, value in params[name].items():
            obj[key] = self._validate_widget_value(value, key)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """return obj's name"""
        return "dashboard"

    @classmethod
    def main(cls):
        module = AnsibleModule(argument_spec=cls.get_argument_spec(), supports_check_mode=True)
        pfmodule = cls(module)
        pfmodule.run(module.params)
        pfmodule.commit_changes()


# Keep the entry point available for Ansible's module test utilities.
main = PFSenseDashboardModule.main

if __name__ == "__main__":
    main()
