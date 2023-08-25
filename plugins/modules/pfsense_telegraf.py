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
module: pfsense_telegraf
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage pfSense telegraf settings
description:
  - Manage pfSense telegraf settings
notes:
options:
  enable:
    description: Enable DNS resolver
    required: false
    type: bool
  interval:
    description: Update Interval
    required: false
    type: int
    default: 10
  telegraf_output:
    description: List of outputs to use
    required: false
    type: list
    choices: ['influxdb', 'elasticsearch', 'graphite']
  influx_server:
    description: Full HTTP or UDP endpoint URL for InfluxDB instance
    required: false
    type: str
  influx_db:
    description: Target database for metrics (created if does not exist)
    required: false
    type: str
  influx_user:
    description: Database user name if required by InfluxDB config
    required: false
    type: str
  influx_pass:
    description: Database password if required by InfluxDB config
    required: false
    type: str
  insecure_skip_verify:
    description: Use SSL but skip chain and host verification
    required: false
    type: bool
  shortname:
    description: Use short hostname instead of FQDN
    required: false
    type: bool
  elasticsearch_server:
    description: Full HTTP endpoint URL for ElasticSearch instance
    required: false
    type: str
  graphite_server:
    description: Graphite Endpoint
    required: false
    type: str
  graphite_prefix:
    description: Prefix to be used when submitting data to Graphite
    required: false
    type: str
  graphite_timeout:
    description: Timeout when submitting data to Graphite
    required: false
    type: str
  haproxy_enable:
    description: Database user name if required by InfluxDB config
    required: false
    type: bool
  haproxy_port:
    description: Port number where HAProxy status is available (default: 2200)
    required: false
    type: int
  netstat_enable:
    description: Enable Netstat Monitor
    required: false
    type: bool
  ping_enable:
    description: Enable Ping Monitor (up to 4 hosts (IPs))
    required: false
    type: bool
  ping_host_1:
    description: Ping Host 1
    required: false
    type: str
  ping_host_2:
    description: Ping Host 2
    required: false
    type: str
  ping_host_3:
    description: Ping Host 3
    required: false
    type: str
  ping_host_4:
    description: Ping Host 4
    required: false
    type: str
  telegraf_raw_config:
    description: Additional configuration for Telegraf
    required: false
    type: str
"""

EXAMPLES = """
- name: setup telegraf
  pfsense_telegraf:
    enable: true
    telegraf_raw_config: |
      [[outputs.prometheus_client]]
      listen = ":9273"
      path = "/"
      metric_version = 2
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["update telegraf set enable=True"]
"""

import base64
from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

base64_params = [
  'telegraf_raw_config'
]

TELEGRAF_ARGUMENT_SPEC = dict(
    enable=dict(required=False, type='bool'),
    interval=dict(required=False, type='int', default=10),
    telegraf_output=dict(required=False, type='list', elements='str',
      choices=['influxdb', 'elasticsearch', 'graphite'], default=[]),
    influx_server=dict(required=False, type='str'),
    influx_db=dict(required=False, type='str'),
    influx_user=dict(required=False, type='str'),
    influx_pass=dict(required=False, type='str', no_log=True),
    insecure_skip_verify=dict(required=False, type='bool', default=False),
    shortname=dict(required=False, type='bool', default=False),
    elasticsearch_server=dict(required=False, type='str'),
    graphite_server=dict(required=False, type='str'),
    graphite_prefix=dict(required=False, type='str'),
    graphite_timeout=dict(required=False, type='int'),
    haproxy_enable=dict(required=False, type='bool', default=False),
    haproxy_port=dict(required=False, type=int, default='2200'),
    netstat_enable=dict(required=False, type='bool', default=False),
    ping_enable=dict(required=False, type='bool', default=False),
    ping_host_1=dict(required=False, type='str'),
    ping_host_2=dict(required=False, type='str'),
    ping_host_3=dict(required=False, type='str'),
    ping_host_4=dict(required=False, type='str'),
    telegraf_raw_config=dict(required=False, type='str'),
)


class PFSenseTelegrafModule(PFSenseModuleBase):
    """ module managing pfsense telegraf settings """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return TELEGRAF_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseTelegrafModule, self).__init__(module, pfsense)
        self.name = "telegraf"
        pkgs_elt = self.pfsense.get_element('installedpackages', create_node=True)
        telegraf_elt = self.pfsense.get_element('telegraf', pkgs_elt, create_node=True)
        self.root_elt = self.pfsense.get_element('config', telegraf_elt, create_node=True)

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params
        obj = self.pfsense.element_to_dict(self.root_elt)
        self.before = deepcopy(obj)
        self.before_elt = deepcopy(self.root_elt)

        from pprint import pformat

        def _set_param(target, param):
            if params.get(param) is not None:
                if isinstance(params[param], str):
                  if param in base64_params:
                    target[param] = base64.b64encode(params[param].encode()).decode()
                  else:
                    target[param] = params[param]
                else:
                  if param in base64_params:
                    target[param] = base64.b64encode('\n'.join(params[param]).encode()).decode()
                  else:
                    target[param] = str(params[param])

        def _set_param_bool(target, param):
            if params.get(param) is not None:
                value = params.get(param)
                if value is True and (param not in target or target[param] != 'on'):
                    target[param] = 'on'
                elif value is False and (param not in target or target[param] != ''):
                    target[param] = ''

        def _set_param_list(target, param):
            if param == 'telegraf_output':
              target[param] = ','.join(params.get(param, []))

        for param in TELEGRAF_ARGUMENT_SPEC:
            if TELEGRAF_ARGUMENT_SPEC[param]['type'] == 'list':
                _set_param_list(obj, param)
            elif TELEGRAF_ARGUMENT_SPEC[param]['type'] == 'bool':
                _set_param_bool(obj, param)
            else:
                _set_param(obj, param)

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        pass

    def run(self, params):
        """ process input params to add/update/delete """
        self.params = params
        self.target_elt = self.root_elt
        self._validate_params()
        self.obj = self._params_to_obj()
        self._add()

    def _update(self):
        """ make the target pfsense reload """
        cmd = '''
require_once("filter.inc");
require_once("telegraf.inc");
$retval = 0;
$retval |= telegraf_resync_config();
'''
        return self.pfsense.phpshell(cmd)

    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "telegraf"

    @staticmethod
    def fvalue_bool(value):
        """ boolean value formatting function """
        if value is None or value is False or value == 'none' or value != 'on':
            return 'False'

        return 'True'

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        for param in TELEGRAF_ARGUMENT_SPEC:
            if TELEGRAF_ARGUMENT_SPEC[param]['type'] == 'bool':
                values += self.format_updated_cli_field(self.obj, self.before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
            else:
                values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

        return values


def main():
    module = AnsibleModule(
        argument_spec=TELEGRAF_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseTelegrafModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
