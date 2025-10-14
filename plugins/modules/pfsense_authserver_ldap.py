#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018-2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_authserver_ldap
version_added: 0.1.0
short_description: Manage pfSense LDAP authentication servers
description:
  >
    Manage pfSense LDAP authentication servers
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name of the authentication server
    required: true
    type: str
  state:
    description: State in which to leave the authentication server
    default: 'present'
    choices: [ "present", "absent" ]
    type: str
  host:
    description: The hostname or IP address of the authentication server
    required: false
    type: str
  port:
    description: Port to connect to
    default: '389'
    type: str
  transport:
    description: Transport to use
    choices: [ "tcp", "starttls", "ssl" ]
    type: str
  ca:
    description: Certificate Authority
    default: global
    type: str
  protver:
    description: LDAP protocol version
    default: '3'
    choices: [ "2", "3" ]
    type: str
  timeout:
    description: Server timeout in seconds
    default: '25'
    type: str
  scope:
    description: Search scope
    choices: [ 'one', 'subtree' ]
    type: str
  basedn:
    description: Search base DN
    type: str
  authcn:
    description: Authentication containers added to basedn
    required: false
    type: str
  extended_enabled:
    description: Enable extended query
    default: False
    type: bool
  extended_query:
    description: Extended query
    default: ''
    type: str
  binddn:
    description: Search bind DN
    type: str
  bindpw:
    description: Search bind password
    type: str
  attr_user:
    description: LDAP User naming attribute
    default: cn
    type: str
  attr_group:
    description: LDAP Group naming attribute
    default: cn
    type: str
  attr_member:
    description: LDAP Group member naming attribute
    default: member
    type: str
  attr_groupobj:
    description: LDAP Group objectClass naming attribute
    default: posixGroup
    type: str
  ldap_rfc2307:
    description: LDAP Server uses RFC 2307 style group membership (RFC 2307bis when False)
    type: bool
  ldap_rfc2307_userdn:
    description: Use DN for username search (pfsense-CE >=2.5.0, pfsense-PLUS >=21.2)
    type: bool
  ldap_utf8:
    description: UTF8 encode LDAP parameters before sending them to the server.
    type: bool
  ldap_nostrip_at:
    description: Do not strip away parts of the username after the @ symbol
    type: bool
  ldap_pam_groupdn:
    description: Shell Authentication Group DN (pfsense-CE >=2.5.0, pfsense-PLUS >=21.2)
    type: str
  ldap_allow_unauthenticated:
    description: Allow unauthenticated bind (pfsense-CE >=2.5.0, pfsense-PLUS >=21.2). Defaults to true.
    type: bool
"""

EXAMPLES = """
- name: Add adservers authentication server
  pfsense_authserver_ldap:
    name: AD
    host: adserver.example.com
    port: 636
    transport: ssl
    scope: subtree
    authcn: cn=users
    basedn: dc=example,dc=com
    binddn: cn=bind,ou=Service Accounts,dc=example,dc=com
    bindpw: "{{ vaulted_bindpw }}"
    attr_user: samAccountName
    attr_member: memberOf
    attr_groupobj: group
    state: present

- name: Remove LDAP authentication server
  pfsense_authserver_ldap:
    name: AD
    state: absent
"""

RETURN = """

"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

PFSENSE_AUTHSERVER_LDAP_SPEC = {
    'name': {'required': True, 'type': 'str'},
    'state': {
        'default': 'present',
        'choices': ['present', 'absent']
    },
    'host': {'type': 'str'},
    'port': {'default': '389', 'type': 'str'},
    'transport': {
        'choices': ['tcp', 'starttls', 'ssl']
    },
    'ca': {'default': 'global', 'type': 'str'},
    'protver': {
        'default': '3',
        'choices': ['2', '3']
    },
    'timeout': {'default': '25', 'type': 'str'},
    'scope': {
        'choices': ['one', 'subtree']
    },
    'basedn': {'required': False, 'type': 'str'},
    'authcn': {'required': False, 'type': 'str'},
    'extended_enabled': {'default': False, 'type': 'bool'},
    'extended_query': {'default': '', 'type': 'str'},
    'binddn': {'required': False, 'type': 'str'},
    'bindpw': {'required': False, 'type': 'str'},
    'attr_user': {'default': 'cn', 'type': 'str'},
    'attr_group': {'default': 'cn', 'type': 'str'},
    'attr_member': {'default': 'member', 'type': 'str'},
    'attr_groupobj': {'default': 'posixGroup', 'type': 'str'},
    'ldap_pam_groupdn': {'required': False, 'type': 'str'},
    'ldap_utf8': {'required': False, 'type': 'bool'},
    'ldap_nostrip_at': {'required': False, 'type': 'bool'},
    'ldap_rfc2307': {'required': False, 'type': 'bool'},
    'ldap_rfc2307_userdn': {'required': False, 'type': 'bool'},
    'ldap_allow_unauthenticated': {'required': False, 'type': 'bool'},
}

AUTHSERVER_LDAP_CREATE_DEFAULT = dict(
    ldap_allow_unauthenticated=None
)

AUTHSERVER_LDAP_PHP_COMMAND = """
require_once('auth.inc');
if (config_path_enabled('system/webgui', 'shellauth') &&
  (config_get_path('system/webgui/authmode') == '{name}')) {{
    set_pam_auth();
}}
"""


class PFSenseAuthserverLDAPModule(PFSenseModuleBase):
    """ module managing pfsense LDAP authentication """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return PFSENSE_AUTHSERVER_LDAP_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseAuthserverLDAPModule, self).__init__(module, pfsense, name='pfsense_authserver_ldap', root='system', node='authserver', key='name',
                                                          have_refid=True, create_default=AUTHSERVER_LDAP_CREATE_DEFAULT)

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """

        if int(self.params['timeout']) < 1:
            self.module.fail_json(msg='timeout {0} must be greater than 1'.format(self.params['timeout']))

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()

        obj['name'] = params['name']
        if params['state'] == 'present':
            obj['type'] = 'ldap'
            for option in ['host']:
                if option in params and params[option] is not None:
                    obj[option] = params[option]

            obj['ldap_port'] = params['port']
            if self.pfsense.config_version >= 20.1:
                urltype = dict({'tcp': 'Standard TCP', 'starttls': 'STARTTLS Encrypted', 'ssl': 'SSL/TLS Encrypted'})
            else:
                urltype = dict({'tcp': 'TCP - Standard', 'starttls': 'TCP - STARTTLS', 'ssl': 'SSL - Encrypted'})
            obj['ldap_urltype'] = urltype[params['transport']]
            obj['ldap_protver'] = params['protver']
            obj['ldap_timeout'] = params['timeout']
            obj['ldap_scope'] = params['scope']
            obj['ldap_basedn'] = params['basedn']
            obj['ldap_authcn'] = params['authcn']
            if params['extended_enabled']:
                obj['ldap_extended_enabled'] = 'yes'
            else:
                obj['ldap_extended_enabled'] = ''
            obj['ldap_extended_query'] = params['extended_query']
            if params['binddn']:
                obj['ldap_binddn'] = params['binddn']
            if params['bindpw']:
                obj['ldap_bindpw'] = params['bindpw']
            obj['ldap_attr_user'] = params['attr_user']
            obj['ldap_attr_group'] = params['attr_group']
            obj['ldap_attr_member'] = params['attr_member']
            obj['ldap_attr_groupobj'] = params['attr_groupobj']
            if params['ldap_utf8']:
                obj['ldap_utf8'] = ''
            if params['ldap_nostrip_at']:
                obj['ldap_nostrip_at'] = ''
            if params['ldap_rfc2307']:
                obj['ldap_rfc2307'] = ''

            if self.pfsense.is_at_least_2_5_0():
                obj['ldap_pam_groupdn'] = params['ldap_pam_groupdn']
                if params['ldap_rfc2307_userdn']:
                    obj['ldap_rfc2307_userdn'] = ''
                if params['ldap_allow_unauthenticated']:
                    obj['ldap_allow_unauthenticated'] = ''

            # Find the caref id for the named CA
            obj['ldap_caref'] = self.pfsense.get_caref(params['ca'])
            # CA is required for SSL/TLS
            if self.pfsense.config_version >= 20.1:
                if obj['ldap_caref'] is None and obj['ldap_urltype'] != 'Standard TCP':
                    self.module.fail_json(msg="Could not find CA '%s'" % (params['ca']))
            else:
                if obj['ldap_caref'] is None and obj['ldap_urltype'] != 'TCP - Standard':
                    self.module.fail_json(msg="Could not find CA '%s'" % (params['ca']))

        return obj

    ##############################
    # XML processing
    #
    def _find_target(self):
        result = self.root_elt.findall("authserver[name='{0}'][type='ldap']".format(self.obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple ldap authentication servers for name {0}.'.format(self.obj['name']))
        else:
            return None

    ##############################
    # run
    #
    def _update(self):
        """ update system configuration if needed """
        return self.pfsense.phpshell(AUTHSERVER_LDAP_PHP_COMMAND.format(name=self.obj['name']))


def main():
    module = AnsibleModule(
        argument_spec=PFSENSE_AUTHSERVER_LDAP_SPEC,
        required_if=[
            ["state", "present", ["host", "port", "transport", "scope", "authcn"]],
        ],
        supports_check_mode=True)

    pfmodule = PFSenseAuthserverLDAPModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
