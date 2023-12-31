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
module: pfsense_hasync
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage pfSense hasync settings
description:
  - Manage pfSense hasync settings
notes:
options:
  pfsyncenabled:
    description: Transfer state insertion, update, and deletion messages between firewalls.
    required: false
    type: bool
  pfsyncinterface:
    description: If pfsyncenabled is true this interface will be used for communication.
    required: false
    type: str
  pfsyncpeerip:
    description: Setting this option will force pfsync to synchronize its state table to this IP address. The default is directed multicast.
    required: false
    type: str
  synchronizetoip:
    description: The IP address of the firewall to which the selected configuration sections should be synchronized.
    required: false
    type: str
  username:
    description: The username of the synchronizetoip system for synchronizing the configuration.
    required: false
    type: str
  password:
    description: The password of the synchronizetoip system for synchronizing the configuration.
    required: false
    type: str
  adminsync:
    description: Synchronize admin accounts and autoupdate sync password.
    required: false
    type: bool
  synchronizeusers:
    description: Sync User manager users and groups
    required: false
    type: bool
  synchronizeauthservers:
    description: Sync Authentication servers (e.g. LDAP, RADIUS)
    required: false
    type: bool
  synchronizecerts:
    description: Sync Certificate Authorities, Certificates, and Certificate Revocation Lists
    required: false
    type: bool
  synchronizerules:
    description: Sync Firewall rules
    required: false
    type: bool
  synchronizeschedules:
    description: Sync Firewall schedules 
    required: false
    type: bool
  synchronizealiases:
    description: Sync Firewall aliases
    required: false
    type: bool
  synchronizenat:
    description: Sync NAT configuration
    required: false
    type: bool
  synchronizeipsec:
    description: Sync IPsec configuration
    required: false
    type: bool
  synchronizeopenvpn:
    description: Sync OpenVPN configuration (Implies CA/Cert/CRL Sync)
    required: false
    type: bool
  synchronizedhcpd:
    description: Sync DHCP Server settings
    required: false
    type: bool
  synchronizewol:
    description: Sync WoL Server settings
    required: false
    type: bool
  synchronizestaticroutes:
    description: Sync Static Route configuration
    required: false
    type: bool
  synchronizevirtualip:
    description: Sync Virtual IPs
    required: false
    type: bool
  synchronizetrafficshaper:
    description: Sync Traffic Shaper configuration
    required: false
    type: bool
  synchronizetrafficshaperlimiter:
    description: Sync Traffic Shaper Limiters configuration
    required: false
    type: bool
  synchronizednsforwarder:
    description: Sync DNS Forwarder and DNS Resolver configurations
    required: false
    type: bool
  synchronizecaptiveportal:
    description: Sync Captive Portal
    required: false
    type: bool
"""

EXAMPLES = """
  pfsensible.core.pfsense_hasync:
    pfsyncenabled: true
    pfsyncpeerip: "192.168.61.12"
    pfsyncinterface: "lan"
    synchronizetoip: "192.168.61.11"
    username: "admin"
    password: "pfsense"
    synchronizerules: true
    synchronizedhcpd: true
"""

RETURN = """
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: [
        "update hasync hasync set pfsyncinterface='lan', pfsyncpeerip='192.168.61.12'"
    ]
"""

import re
from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


HASYNC_ARGUMENT_SPEC = dict(
    pfsyncenabled=dict(required=False, type='bool'),
    pfsyncinterface=dict(required=False, type='str'),
    pfsyncpeerip=dict(required=False, type='str'),
    synchronizetoip=dict(required=False, type='str'),
    username=dict(required=False, type='str'),
    password=dict(required=False, type='str', no_log=True),
    adminsync=dict(required=False, type='bool'),
    synchronizeusers=dict(required=False, type='bool'),
    synchronizeauthservers=dict(required=False, type='bool'),
    synchronizecerts=dict(required=False, type='bool'),
    synchronizerules=dict(required=False, type='bool'),
    synchronizeschedules=dict(required=False, type='bool'),
    synchronizealiases=dict(required=False, type='bool'),
    synchronizenat=dict(required=False, type='bool'),
    synchronizeipsec=dict(required=False, type='bool'),
    synchronizeopenvpn=dict(required=False, type='bool'),
    synchronizedhcpd=dict(required=False, type='bool'),
    synchronizewol=dict(required=False, type='bool'),
    synchronizestaticroutes=dict(required=False, type='bool'),
    synchronizevirtualip=dict(required=False, type='bool'),
    synchronizetrafficshaper=dict(required=False, type='bool'),
    synchronizetrafficshaperlimiter=dict(required=False, type='bool'),
    synchronizednsforwarder=dict(required=False, type='bool'),
    synchronizecaptiveportal=dict(required=False, type='bool'),
)

class PFSenseHASyncModule(PFSenseModuleBase):
    """ module managing pfsense hasync settings """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return HASYNC_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseHASyncModule, self).__init__(module, pfsense)
        self.name = "hasync"
        self.root_elt = self.pfsense.get_element('hasync')
        self.target_elt = self.root_elt
        self.params = dict()
        self.obj = dict()
        self.before = None
        self.before_elt = None
        self.route_cmds = list()
        self.params_to_delete = list()

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = self.pfsense.element_to_dict(self.root_elt)
        self.before = deepcopy(obj)
        self.before_elt = deepcopy(self.root_elt)

        def _set_param(target, param):
            # get possibly mapped settings name
            if params.get(param) is not None:
                if isinstance(params[param], str):
                    target[param] = params[param]
                else:
                    target[param] = str(params[param])

        def _set_param_bool(target, param):
            # get possibly mapped settings name
            if params.get(param) is not None:
                value = params.get(param)
                if value is True and param not in target:
                    target[param] = 'on'
                elif value is False and param in target:
                    del target[param]

        for param in HASYNC_ARGUMENT_SPEC:
            if HASYNC_ARGUMENT_SPEC[param]['type'] == 'bool':
                _set_param_bool(obj, param)
            else:
                _set_param(obj, param)

        return obj


    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params
        return

    ##############################
    # XML processing
    #
    def _remove_deleted_params(self):
        """ Remove from target_elt a few deleted params """
        changed = False
        for param in HASYNC_ARGUMENT_SPEC:
            if HASYNC_ARGUMENT_SPEC[param]['type'] == 'bool':
                if self.pfsense.remove_deleted_param_from_elt(self.target_elt, param, self.obj):
                    changed = True

        return changed

    ##############################
    # run
    #
    def run(self, params):
        """ process input params to add/update/delete """
        self.params = params
        self.target_elt = self.root_elt
        self._validate_params()
        self.obj = self._params_to_obj()
        self._add()

    def _update(self):
        """ make the target pfsense reload """
        for cmd in self.route_cmds:
            self.module.run_command(cmd)
        cmd = '''
require_once("interfaces.inc");
$retval = 0;
$retval |= interfaces_sync_setup();'''

        return self.pfsense.phpshell(cmd)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "hasync_settings"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        for param in HASYNC_ARGUMENT_SPEC:
            if HASYNC_ARGUMENT_SPEC[param]['type'] == 'bool':
                values += self.format_updated_cli_field(self.obj, self.before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
            else:
                values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

        return values


def main():
    module = AnsibleModule(
        argument_spec=HASYNC_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseHASyncModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
