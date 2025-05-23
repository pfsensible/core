#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_rfc2136

short_description: Manage pfSense RFC 2136 dynamic DNS updates

version_added: "0.8.0"

description:
  - Manage pfSense RFC 2136 dynamic DNS updates.
  - Changes to an enabled entry trigger a forced update for its hostname.
  - Disabling or deleting an entry leaves its existing DNS records on the server.

options:
  descr:
    description: The description of the RFC 2136 DDNS update. This is used as a unique key by pfSensible.
    required: true
    type: str
  state:
    description: State in which to leave the RFC 2136 DDNS update.
    default: present
    choices: ['present', 'absent']
    type: str
  enable:
    description:
      - Enable the RFC 2136 DDNS update.
      - New entries are disabled when omitted.
    type: bool
  interface:
    description:
      - Interface or gateway group to monitor. Its address is used in the updated DNS record.
      - Defaults to C(wan) for new entries.
    type: str
  host:
    description:
      - DNS name of the host to update.
      - Required when O(state=present).
    type: str
  zone:
    description:
      - DNS zone containing O(host). Use an empty string for automatic discovery.
    type: str
  ttl:
    description:
      - TTL of the DNS record in seconds, from 0 to 2147483647.
      - Required when O(state=present).
    type: int
  keyname:
    description:
      - TSIG key name configured on the DNS server.
      - Required when O(state=present).
    type: str
  keyalgorithm:
    description:
      - TSIG key algorithm.
      - New entries default to the legacy pfSense algorithm C(hmac-md5).
    choices: ['hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512']
    type: str
  keydata:
    description:
      - Base64-encoded TSIG secret.
      - Required when O(state=present).
    type: str
  server:
    description:
      - DNS update server hostname or IP address, optionally followed by a space and port.
      - Use an empty string for automatic discovery.
    type: str
  usetcp:
    description: Use TCP instead of UDP.
    type: bool
  usepublicip:
    description: If the interface IP is private, attempt to fetch and use the public IP instead.
    type: bool
  updatesource:
    description:
      - Interface or IP address from which the firewall sends the DNS update request.
      - Use an empty string to bind to the monitored interface address, or C(none) to let the system select the source.
      - New entries default to an empty string.
    type: str
  updatesourcefamily:
    description:
      - Address family for the source address. An empty string selects the family automatically.
      - New entries default to an empty string.
    choices: ['', 'inet', 'inet6']
    type: str
  recordtype:
    description:
      - Record type to update.
      - Defaults to C(both) for new entries.
    choices: ['A', 'AAAA', 'both']
    type: str

author: Orion Poplawski (@opoplawski)
"""

EXAMPLES = r"""
- name: Configure a signed DNS update
  pfsensible.core.pfsense_rfc2136:
    descr: Office IPv4
    enable: true
    interface: WAN
    host: office.example.com
    zone: example.com
    ttl: 600
    keyname: office-update.example.com
    keyalgorithm: hmac-sha256
    keydata: "{{ vault_ddns_tsig_secret }}"
    server: 192.0.2.53
    recordtype: A

- name: Remove the DNS update entry
  pfsensible.core.pfsense_rfc2136:
    descr: Office IPv4
    state: absent
"""
RETURN = r"""
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: ["create rfc2136 'myitem'", "update rfc2136 'myitem' set ...", "delete rfc2136 'myitem'"]
"""

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.arg_route import p2o_interface_with_gwgroup
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


RFC2136_ARGUMENT_SPEC = dict(
    descr=dict(required=True, type="str"),
    enable=dict(type="bool"),
    state=dict(type="str", default="present", choices=["present", "absent"]),
    interface=dict(type="str"),
    host=dict(type="str"),
    zone=dict(type="str"),
    ttl=dict(type="int"),
    keyname=dict(type="str"),
    keyalgorithm=dict(type="str", choices=["hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512"]),
    keydata=dict(type="str", no_log=True),
    server=dict(type="str"),
    usetcp=dict(type="bool"),
    usepublicip=dict(type="bool"),
    updatesource=dict(type="str"),
    updatesourcefamily=dict(type="str", choices=["", "inet", "inet6"]),
    recordtype=dict(type="str", choices=["A", "AAAA", "both"]),
)

RFC2136_REQUIRED_IF = [
    ["state", "present", ["host", "ttl", "keyname", "keydata"]],
]

RFC2136_CREATE_DEFAULT = dict(
    interface="wan",
    zone="",
    keyalgorithm="hmac-md5",
    server="",
    updatesource="",
    updatesourcefamily="",
    recordtype="both",
)

DNS_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")


def valid_dns_name(value):
    """Accept DNS labels and an optional root dot."""
    name = value[:-1] if value.endswith(".") else value
    return len(name) <= 253 and all(DNS_LABEL.fullmatch(label) for label in name.split("."))


def p2o_host(self, name, params, obj):
    # pfSense's nsupdate command builder adds the hostname's root dot.
    obj[name] = params[name].rstrip(".")


def p2o_updatesource(self, name, params, obj):
    value = params[name]
    if value in ("", "none") or self.pfsense.is_ipv4_address(value) or ("%" not in value and self.pfsense.is_ipv6_address(value)):
        obj[name] = value
    else:
        obj[name] = self.pfsense.parse_interface(value, with_virtual=False)


class PFSenseRfc2136Module(PFSenseModuleBase):
    """Manage pfSense RFC 2136 clients."""

    @staticmethod
    def get_argument_spec():
        return RFC2136_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseRfc2136Module, self).__init__(
            module,
            pfsense,
            name="pfsense_rfc2136",
            root="dnsupdates",
            node="dnsupdate",
            arg_route=dict(interface=dict(parse=p2o_interface_with_gwgroup), host=dict(parse=p2o_host), updatesource=dict(parse=p2o_updatesource)),
            create_default=RFC2136_CREATE_DEFAULT,
            create_root=True,
            bool_style="absent/present",
        )

    def _validate_params(self):
        if not self.params["descr"].strip():
            self.module.fail_json(msg="descr must not be empty")
        if self.params["state"] == "absent":
            return

        for field in ("host", "zone", "keyname"):
            value = self.params[field]
            if (field != "zone" or value) and not valid_dns_name(value):
                self.module.fail_json(msg=f"{field} must be a valid DNS name")

        ttl = self.params["ttl"]
        if isinstance(ttl, bool) or not 0 <= ttl <= 2147483647:
            self.module.fail_json(msg="ttl must be an integer between 0 and 2147483647")

        try:
            if not base64.b64decode(self.params["keydata"], validate=True):
                raise ValueError
        except ValueError:
            self.module.fail_json(msg="keydata must be a nonempty base64-encoded TSIG secret")

        server = self.params["server"]
        if server:
            address, separator, port = server.partition(" ")
            if not (
                self.pfsense.is_ipv4_address(address)
                or ("%" not in address and self.pfsense.is_ipv6_address(address))
                or (valid_dns_name(address) and not re.fullmatch(r"[0-9.]+", address))
            ):
                self.module.fail_json(msg="server must use a hostname or an IPv4 or IPv6 address")
            if separator and (not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535):
                self.module.fail_json(msg="server port must be an integer between 1 and 65535")

    def _find_target(self):
        descr = self.obj[self.key]
        matches = [entry for entry in self.elements if entry.findtext(self.key) == descr]
        if len(matches) > 1:
            self.module.fail_json(msg=f"Found multiple RFC 2136 entries for descr {descr}.")
        return matches[0] if matches else None

    def format_cli_field(self, after, field, **kwargs):
        if field == "keydata" and field in after:
            after = dict(after, keydata="VALUE_SPECIFIED_IN_NO_LOG_PARAMETER")
        return super(PFSenseRfc2136Module, self).format_cli_field(after, field, **kwargs)

    def _run_post(self):
        # Ansible can only redact secrets supplied in the current task.
        for side, snapshot in self.diff.items():
            if "keydata" in snapshot:
                self.diff[side] = dict(snapshot, keydata="VALUE_SPECIFIED_IN_NO_LOG_PARAMETER")

    def _update(self):
        if self.params["state"] == "absent" or self.target_elt.find("enable") is None:
            return (0, "", "")
        # Use the GUI's force-update path so cached addresses do not suppress edits.
        host = self.obj["host"]
        return self.pfsense.phpshell(f"""require_once("services.inc"); services_dnsupdate_process("", "{host}", true);""", debug=False)


def main():
    module = AnsibleModule(argument_spec=RFC2136_ARGUMENT_SPEC, required_if=RFC2136_REQUIRED_IF, supports_check_mode=True)

    pfmodule = PFSenseRfc2136Module(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
