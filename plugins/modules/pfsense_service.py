#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Peter B. Dick <peter.dick@fovea.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_service
version_added: "0.4.3"
author: Peter B. Dick
short_description: Adds a service to PFSense config settings
description:
  - Adds a service to PFSense config settings
notes:
options:
  name:
    description: The name of the service
    required: true
    type: str
  rcfile:
    description: The name of the rc file
    required: true
    type: str
  executable:
    description: The name of the executable
    required: true
    type: str
  description:
    description: This parameter is not yet supported!
    required: false
    type: str
"""

EXAMPLES = """
- name: add a service
  pfsense_service:
    name: filebeat
    rcfile: filebeat
    executable: filebeat
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["services add filebeat"]
"""

from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

SERVICE_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    rcfile=dict(required=True, type='str'),
    executable=dict(required=True, type='str'),
    description=dict(default='', required=False, type='str'),
)


class PFSenseServiceModule(PFSenseModuleBase):
    """ module managing pfsense Service settings """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return SERVICE_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseServiceModule, self).__init__(module, pfsense)
        self.serviceElement = None
        self.name = "pfsense_service"
        self.installedPackagesElement = self.pfsense.get_element('installedpackages', create_node=True)

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params
        obj = self.pfsense.element_to_dict(self.serviceElement)
        self.before = deepcopy(obj)
        self.before_elt = deepcopy(self.serviceElement)

        def _set_param(target, param):
            if params.get(param) is not None:
                if isinstance(params[param], str):
                    target[param] = params[param]
                else:
                    target[param] = str(params[param])

        for param in SERVICE_ARGUMENT_SPEC:
            _set_param(obj, param)

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        pass

    def run(self, params):
        """ process input params to add/update/delete """
        self.params = params

        # find given name for service in parameter name
        serviceName = params.get('name')

        # find service for service name
        for service in self.installedPackagesElement.findall('service'):
            if service is not None:
                name = service.find('name').text
                if serviceName == name:
                    self.serviceElement = service

        # add a new new service if none exist with the given parameter name
        if self.serviceElement is None:
            self.serviceElement = self.pfsense.new_element('service')
            self.installedPackagesElement.append(self.serviceElement)

        self.target_elt = self.serviceElement
        self._validate_params()
        self.obj = self._params_to_obj()
        self._add()

    def _update(self):
        """ make the target pfsense reload """
        cmd = '''
require_once("filter.inc");
require_once("Service.inc");
$retval = 0;
$retval |= Service_resync_config();
'''
        return self.pfsense.phpshell(cmd)

    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "Service"

    @staticmethod
    def fvalue_bool(value):
        """ boolean value formatting function """
        if value is None or value is False or value == 'none' or value != 'on':
            return 'False'

        return 'True'

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        for param in SERVICE_ARGUMENT_SPEC:
            if SERVICE_ARGUMENT_SPEC[param]['type'] == 'bool':
                values += self.format_updated_cli_field(self.obj, self.before, param, fvalue=self.fvalue_bool,
                                                        add_comma=(values), log_none=False)
            else:
                values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values),
                                                        log_none=False)

        return values


def main():
    module = AnsibleModule(
        argument_spec=SERVICE_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseServiceModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
