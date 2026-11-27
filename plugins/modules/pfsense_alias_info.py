#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: pfsense_alias_info
short_description: List pfSense aliases, their contents, and usage status
version_added: "0.8.0"
author: pfsensible maintainers (@pfsensible)
description:
  - Read the saved configuration on the managed pfSense firewall and report aliases and their usage status.
  - The module checks configured firewall and NAT rules (including disabled rules), static routes, and OpenVPN settings for alias references.
  - Nested aliases are considered used when they are reachable from a configured reference outside the alias definitions.
    An entire group of aliases can be unused if nothing outside that group references it.
  - Package settings and references generated at runtime are outside the scope of the report.
options:
  only_unused:
    description: Return only unused aliases.
    type: bool
    default: false
attributes:
  check_mode:
    description: Returns the same report in check mode.
    support: full
"""

EXAMPLES = """
- name: List all aliases on this firewall
  pfsensible.core.pfsense_alias_info:
  register: alias_report

- name: Find unused aliases on this firewall
  pfsensible.core.pfsense_alias_info:
    only_unused: true
  register: unused_alias_report

- name: Show unused aliases and their contents
  ansible.builtin.debug:
    var: unused_alias_report.aliases
"""

RETURN = """
aliases:
  description: Alias definitions in configuration order, filtered to unused aliases when O(only_unused=true).
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description: Alias name.
      type: str
    type:
      description: Alias type as stored in the configuration.
      type: str
    unused:
      description: Whether this alias has no direct or nested reference from the settings checked by the module.
      type: bool
    address:
      description:
        - Configured contents, such as space-separated addresses, networks, hostnames, ports, or nested alias names.
        - For URL table aliases the report contains the configured URL fields when present. The module reads only the saved configuration.
      type: str
    descr:
      description: Alias description, when present.
      type: str
    detail:
      description: Entry descriptions in the pfSense configuration format, when present.
      type: str
    url:
      description: Configured URL for a URL table alias, when present.
      type: str
    aliasurl:
      description: Configured source URLs for URL aliases, when present.
      type: list
      elements: str
    updatefreq:
      description: Update interval in days as stored in the configuration, when present.
      type: str
  sample:
    - name: old_web_servers
      type: host
      unused: true
      address: 192.0.2.10 192.0.2.11
      descr: Retired web servers
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.alias_references import ALIAS_REFERENCE_FIELDS, alias_reference_names
from ansible_collections.pfsensible.core.plugins.module_utils.pfsense import PFSenseModule


def get_aliases(root, only_unused):
    """Report whether each alias can be reached from a configured reference."""
    aliases = [(alias.findtext("name"), alias) for alias in root.findall("aliases/alias") if alias.findtext("name")]
    if not aliases:
        return []

    names = {name for name, alias in aliases}
    referenced = set()
    for section, fields in ALIAS_REFERENCE_FIELDS.items():
        if section == "aliases/alias":
            continue
        for entry in root.iterfind(section):
            for field in fields:
                referenced.update(names.intersection(alias_reference_names(section, field, entry.findtext(field, ""))))

    # Only start from references outside the alias definitions. This also
    # handles cycles and marks unreferenced alias groups as unused.
    members = {name: set() for name in names}
    for name, alias in aliases:
        members[name].update(names.intersection(alias_reference_names("aliases/alias", "address", alias.findtext("address", ""))))
    pending = list(referenced)
    while pending:
        children = members[pending.pop()] - referenced
        referenced.update(children)
        pending.extend(children)

    result = []
    for name, element in aliases:
        unused = name not in referenced
        if only_unused and not unused:
            continue
        alias = PFSenseModule.element_to_dict(element)
        alias["unused"] = unused
        alias.setdefault("address", "")
        if isinstance(alias.get("aliasurl"), str):
            alias["aliasurl"] = [alias["aliasurl"]]
        result.append(alias)
    return result


def main():
    module = AnsibleModule(argument_spec=dict(only_unused=dict(type="bool", default=False)), supports_check_mode=True)
    pfsense = PFSenseModule(module)
    module.exit_json(changed=False, aliases=get_aliases(pfsense.root, module.params["only_unused"]))


if __name__ == "__main__":
    main()
