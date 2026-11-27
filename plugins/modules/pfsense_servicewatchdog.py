#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: pfsense_servicewatchdog

short_description: Manage pfSense Service Watchdog entries

version_added: "0.8.0"

description:
  - Manage the services that pfSense Service Watchdog monitors and restarts when stopped.

requirements:
  - The Service Watchdog package must be installed on the target pfSense system.

options:
  name:
    description: The internal pfSense service name, such as C(syslogd).
    required: true
    type: str
  state:
    description: State in which to leave the service watchdog entry.
    default: present
    choices: ['present', 'absent']
    type: str
  notify:
    description:
      - Send a notification when Service Watchdog detects the service has stopped and attempts to restart it.
      - When omitted, new entries have notifications disabled and existing entries keep their setting.
    type: bool
  mode:
    description:
      - OpenVPN instance mode, used together with I(vpnid).
      - Specify both options to select an instance when multiple entries or available services match I(name).
    type: str
    choices: ['client', 'server']
  vpnid:
    description: OpenVPN instance ID, used together with I(mode).
    type: int
  zone:
    description:
      - Captive Portal zone name when I(name) is C(captiveportal).
      - Specify the zone to select an instance when multiple entries or available services match I(name).
    type: str

author: Orion Poplawski (@opoplawski)
"""

EXAMPLES = r"""
- name: Monitor syslogd
  pfsensible.core.pfsense_servicewatchdog:
    name: syslogd
    notify: true
    state: present

- name: Monitor a specific OpenVPN server
  pfsensible.core.pfsense_servicewatchdog:
    name: openvpn
    mode: server
    vpnid: 1

- name: Stop monitoring syslogd
  pfsensible.core.pfsense_servicewatchdog:
    name: syslogd
    state: absent
"""
RETURN = r"""
commands:
    description: Commands describing the changes to the watchdog entry.
    returned: always
    type: list
    elements: str
    sample: ["create servicewatchdog 'myitem'", "update servicewatchdog 'myitem' set ...", "delete servicewatchdog 'myitem'"]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

SERVICEWATCHDOG_ARGUMENT_SPEC = dict(
    name=dict(required=True, type="str"),
    state=dict(type="str", default="present", choices=["present", "absent"]),
    notify=dict(type="bool"),
    mode=dict(type="str", choices=["client", "server"]),
    vpnid=dict(type="int"),
    zone=dict(type="str"),
)

SERVICEWATCHDOG_SERVICES_PHP = """
require_once("functions.inc");
require_once("config.inc");
require_once("service-utils.inc");
echo json_encode(array_values(get_services()));
"""

SERVICEWATCHDOG_UPDATE_PHP = """
require_once("/usr/local/pkg/servicewatchdog.inc");
servicewatchdog_cron_job();
"""


class PFSenseServicewatchdogAddModule(PFSenseModuleBase):
    """Manage pfSense Service Watchdog entries."""

    @staticmethod
    def get_argument_spec():
        return SERVICEWATCHDOG_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseServicewatchdogAddModule, self).__init__(
            module,
            pfsense,
            package="Service Watchdog",
            name="pfsense_servicewatchdog",
            root="servicewatchdog",
            node="item",
            key="name",
            create_root=True,
            bool_style="absent/present",
            update_php=SERVICEWATCHDOG_UPDATE_PHP,
        )

    def _validate_params(self):
        name = self.params["name"]
        mode, vpnid, zone = (self.params.get(field) for field in ("mode", "vpnid", "zone"))
        if not name.strip():
            self.module.fail_json(msg="name must be a non-empty service name")
        if name == "cron" and self.params["state"] == "present":
            self.module.fail_json(msg="Service 'cron' cannot be monitored by Service Watchdog")
        if (mode is not None or vpnid is not None) and (name != "openvpn" or mode is None or vpnid is None):
            self.module.fail_json(msg="mode and vpnid must be supplied together for an OpenVPN service")
        if vpnid is not None and vpnid < 1:
            self.module.fail_json(msg="vpnid must be positive")
        if zone is not None and (name != "captiveportal" or not zone.strip()):
            self.module.fail_json(msg="zone must be a non-empty Captive Portal zone name")

    def _matches_service(self, get_value):
        for field in ("name", "mode", "vpnid", "zone"):
            expected = self.params.get(field)
            actual = get_value(field)
            if expected is not None and (actual is None or str(actual) != str(expected)):
                return False
        return True

    def _find_target(self):
        matches = [entry for entry in self.elements if self._matches_service(entry.findtext)]
        return self._select_service(matches, "Service Watchdog entries")

    def _select_service(self, matches, source):
        if len(matches) > 1:
            name = self.params["name"]
            hint = {"openvpn": " Specify mode and vpnid.", "captiveportal": " Specify zone."}
            selector = hint.get(name, "") if self.params.get("mode") is None and self.params.get("zone") is None else ""
            self.module.fail_json(msg=f"Found multiple {source} matching service '{name}'.{selector}")
        return matches[0] if matches else None

    def _add(self):
        if self.target_elt is None:
            services = self.pfsense.php(SERVICEWATCHDOG_SERVICES_PHP)
            if not isinstance(services, list):
                self.module.fail_json(msg="pfSense returned an invalid service inventory")
            matches = [service for service in services if isinstance(service, dict) and self._matches_service(service.get)]
            service = self._select_service(matches, "available services")
            if service is None:
                self.module.fail_json(msg=f"No available service matches '{self.params['name']}' and the supplied instance options")

            # Watchdog uses description in notifications and the instance fields
            # in status checks and restarts. Runtime status can change independently.
            self.obj["description"] = service.get("description") or service["name"]
            for field in ("mode", "vpnid", "zone"):
                if field in service:
                    self.obj[field] = str(service[field])
        super()._add()

    def _update(self):
        rc, stdout, stderr = self.pfsense.phpshell(self.update_php, debug=False)
        if rc:
            self.module.fail_json(msg="Failed to update the Service Watchdog cron job", changed=True, rc=rc, stdout=stdout, stderr=stderr)
        return rc, stdout, stderr


def main():
    module = AnsibleModule(argument_spec=SERVICEWATCHDOG_ARGUMENT_SPEC, supports_check_mode=True)

    pfmodule = PFSenseServicewatchdogAddModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
