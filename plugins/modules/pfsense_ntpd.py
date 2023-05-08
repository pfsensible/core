#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2021, Jan Wenzel <jan.wenzel@gonicus.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_ntpd
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage ntp service settings
description:
    - Manage pfSense ntp service settings.
notes: NTP Peers without options must be set via pfsense_setup
options:
    enable:
        description: Enable NTP Service
        required: false
        type: bool
    orphan:
        description: Stratum of local clock when in orphan mode
        required: false
        type: int
        default: 12
    interface:
        description: Interfaces to listen on
        required: false
        type: list
    timeservers:
        description: NTP Peers
        required: false
        type: list
        elements: dict
        suboptions:
            server:
                description: NTP Host
                required: true
                type: str
            prefer:
                description: Prefer flag
                required: false
                type: bool
            noselect:
                description: Noselect flag
                required: false
                type: bool
            ispool:
                description: server is pool
                required: false
                type: bool
    dnsresolv:
        description: DNS Resolution Behaviour
        required: false
        type: str
        choices: ['auto', 'inet', 'inet6']
    ntpminpoll:
        description: Minimum Poll Interval (pfsense-CE >=2.5.0, pfsense-PLUS >=21.2)
        required: false
        type: raw
        choices: ['', 'omit', 5-17]
    ntpmaxpoll:
        description: Minimum Poll Interval (pfsense-CE >=2.5.0, pfsense-PLUS >=21.2)
        required: false
        type: raw
        choices: ['', 'omit', 5-17]
    statsgraph:
        description: Enable RRD graphs of NTP statistics
        required: false
        type: bool
    logpeer:
        description: Log peer messages
        required: false
        type: bool
    logsys:
        description: Log system messages
        required: false
        type: bool
"""

EXAMPLES = """
"""

RETURN = """
"""

from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.pfsense import PFSenseModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

NTP_TIMESERVER_ARGUMENT_SPEC = dict(
    server=dict(required=True, type='str'),
    prefer=dict(required=False, type='bool'),
    noselect=dict(required=False, type='bool'),
    ispool=dict(required=False, type='bool'),
)

NTP_SERVICE_ARGUMENT_SPEC = dict(
    enable=dict(required=False, type='bool', default=True),
    orphan=dict(required=False, type='int', default=12),
    interface=dict(required=False, type='list', elements='str'),
    timeservers=dict(required=False, type='list', elements='dict',
        options=NTP_TIMESERVER_ARGUMENT_SPEC),
    dnsresolv=dict(required=False, type='str',
        choices=['auto', 'inet', 'inet6'], default='auto'),
    ntpminpoll=dict(required=False, type='raw',
        choices=['', 'omit', 5, 6, 7, 8, 9, 10, 11, 12, 13,
        14, 15, 16, 17], default=''),
    ntpmaxpoll=dict(required=False, type='raw',
        choices=['', 'omit', 5, 6, 7, 8, 9, 10, 11, 12, 13,
        14, 15, 16, 17], default=''),
    statsgraph=dict(required=False, type='bool'),
    logpeer=dict(required=False, type='bool'),
    logsys=dict(required=False, type='bool'),
)


class PFSenseNtpServiceModule(PFSenseModuleBase):
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return NTP_SERVICE_ARGUMENT_SPEC(PFSenseModuleBase)

    def __init__(self, module, pfsense=None):
        super(PFSenseNtpServiceModule, self).__init__(module, pfsense)
        self.name = "pfsense_ntpd_config"
        self.obj = dict()
        self.before = None
        self.before_elt = None
        self.root_elt = self.pfsense.get_element('ntpd', create_node=True)
        self.system_elt = self.pfsense.get_element('system')

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params
        obj = self.pfsense.element_to_dict(self.root_elt)
        self.before = deepcopy(obj)
        self.before_elt = deepcopy(self.root_elt)

        def _set_param(target, param):
            if params.get(param) is not None:
                if param in ['ntpminpoll', 'ntpmaxpoll']:
                    if self.pfsense.is_at_least_2_5_0():
                        if isinstance(params[param], str):
                            target[param] = params[param]
                        else:
                            target[param] = str(params[param])
                else:
                    if isinstance(params[param], str):
                        target[param] = params[param]
                    else:
                        target[param] = str(params[param])

        def _set_param_bool(target, param):
            if params.get(param) is not None:
                value = params.get(param)
                if param == 'enable':
                    if value is True and (param not in target or target[param] != 'enabled'):
                        target[param] = 'enabled'
                    elif value is False and (param not in target or target[param] != ''):
                        target[param] = ''
                else:
                    if value is True and (param not in target or target[param] != 'yes'):
                        target[param] = 'yes'
                    elif value is False and (param not in target or target[param] != ''):
                        target[param] = ''

        def _set_param_list(target, param):
            if params.get(param) is not None:
                if param == 'timeservers':
                    noselect = []
                    ispool = []
                    prefer = []
                    for timeserver in params.get(param):
                        if timeserver.get('ispool', False) is True:
                            ispool.append(timeserver.get('server'))
                        if timeserver.get('noselect', False) is True:
                            noselect.append(timeserver.get('server'))
                        if timeserver.get('prefer', False) is True:
                            prefer.append(timeserver.get('server'))
                    if noselect:
                        target['noselect'] = ' '.join(noselect)
                    if ispool:
                        target['ispool'] = ' '.join(ispool)
                    if prefer:
                        target['prefer'] = ' '.join(prefer)
                if param == 'interface':
                    target[param] = ','.join(params.get(param))

        for param in NTP_SERVICE_ARGUMENT_SPEC:
            if NTP_SERVICE_ARGUMENT_SPEC[param]['type'] == 'bool':
                _set_param_bool(obj, param)
            elif NTP_SERVICE_ARGUMENT_SPEC[param]['type'] == 'list':
                _set_param_list(obj, param)
            else:
                _set_param(obj, param)

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        pass

    def run(self, params):
        self.params = params
        self.target_elt = self.root_elt
        self._validate_params()
        self.obj = self._params_to_obj()
        self._add()

    def _update(self):
        """ make the target pfsense reload """
        cmd = '''
require_once("auth.inc");
require_once("filter.inc");
$retval = 0;
$retval |= system_ntp_configure();'''
        return self.pfsense.phpshell(cmd)

    @staticmethod
    def _get_obj_name():
        return "ntpd"

    def _log_fields(self, before=None):
        values = ''

        if before is None:
            for param in NTP_SERVICE_ARGUMENT_SPEC:
                if NTP_SERVICE_ARGUMENT_SPEC[param]['type'] == 'bool':
                    values += self.format_cli_field(self.obj, param, fvalue=self.fvalue_bool)
                else:
                    values += self.format_cli_field(self.obj, param)
        else:
            for param in NTP_SERVICE_ARGUMENT_SPEC:
                if NTP_SERVICE_ARGUMENT_SPEC[param]['type'] == 'bool':
                    values += self.format_updated_cli_field(self.obj, self.before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
                else:
                    values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

        return values

def main():
    module = AnsibleModule(
        argument_spec=NTP_SERVICE_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseNtpServiceModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
