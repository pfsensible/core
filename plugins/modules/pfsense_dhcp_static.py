#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Carlos Rodrigues <cmarodrigues@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_dhcp_static
version_added: "0.5.0"
author: Carlos Rodrigues (@cmarodrigues)
short_description: Manage pfSense DHCP static mapping
description:
  - Manage pfSense DHCP static mapping
notes:
options:
  name:
    description: The client name identifier.  At least one of I(name) or I(macaddr) is required.
    type: str
    aliases:
      - cid
  netif:
    description: >
      The network interface.  This defaults to the only enabled DHCP interface if there is only one.
    type: str
  macaddr:
    description: The mac address.  At least one of I(name) or I(macaddr) is required.
    type: str
  ipaddr:
    description: The IP address
    type: str
  hostname:
    description: The hostname
    type: str
  descr:
    description: The description
    type: str
  filename:
    description: The filename
    type: str
  rootpath:
    description: The roothpath
    type: str
  defaultleasetime:
    description: the default lease time
    type: str
  maxleasetime:
    description: The max lease time
    type: str
  gateway:
    description: The gateway
    type: str
  domain:
    description: The domain
    type: str
  winsserver:
    description: The WINS server
    type: list
    elements: str
  dnsserver:
    description: The dns server
    type: list
    elements: str
  ntpserver:
    description: The ntpserver
    type: list
    elements: str
  domainsearchlist:
    description: The domain search list servers
    type: str
  ddnsdomain:
    description: The ddns domain
    type: str
  ddnsdomainprimary:
    description: The ddns primary domain
    type: str
  ddnsdomainsecondary:
    description: The ddns secondary domain
    type: str
  ddnsdomainkeyname:
    description: The ddns domain key name
    type: str
  ddnsdomainkeyalgorithm:
    description: The ddns key algorithm
    type: str
    choices: [ 'hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512' ]
  ddnsdomainkey:
    description: The ddns domain key
    type: str
  tftp:
    description: The TFTP server
    type: str
  ldap:
    description: The ldap server
    type: str
  nextserver:
    description: The next server
    type: str
  filename32:
    description: The filename for 32bits
    type: str
  filename64:
    description: The filename for 64bits
    type: str
  filename32arm:
    description: The filename for 32arm
    type: str
  filename64arm:
    description: The filename for 64arm
    type: str
  uefihttpboot:
    description: UEFI HTTPBoot URL
    type: str
    version_added: "0.5.2"
  numberoptions:
    description: The number options
    type: str
  state:
    description: State in which to leave the configuration
    default: present
    choices: [ "present", "absent" ]
    type: str
"""

EXAMPLES = """
- name: Create DHCP static mapping
  pfsense_dhcp_static:
    name: "test"
    macaddr: "aa:aa:aa:aa:aa:aa"
    ipaddr: "192.168.1.10"
    state: present

- name: Remove DHCP static mapping
  pfsense_dhcp_static:
    name: "test"
    state: absent
"""

RETURN = """

"""

from ipaddress import ip_address, ip_network
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

DHCP_STATIC_ARGUMENT_SPEC = dict(
    name=dict(type='str', aliases=['cid']),
    macaddr=dict(type='str'),
    netif=dict(type='str'),
    ipaddr=dict(type='str'),
    hostname=dict(type='str'),
    descr=dict(type='str'),
    filename=dict(type='str'),
    rootpath=dict(type='str'),
    defaultleasetime=dict(type='str'),
    maxleasetime=dict(type='str'),
    gateway=dict(type='str'),
    domain=dict(type='str'),
    domainsearchlist=dict(type='str'),
    winsserver=dict(type='list', elements='str'),
    dnsserver=dict(type='list', elements='str'),
    ntpserver=dict(type='list', elements='str'),
    ddnsdomain=dict(type='str'),
    ddnsdomainprimary=dict(type='str'),
    ddnsdomainsecondary=dict(type='str'),
    ddnsdomainkeyname=dict(type='str'),
    ddnsdomainkeyalgorithm=dict(type='str', choices=['hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512']),
    ddnsdomainkey=dict(type='str', no_log=True),
    tftp=dict(type='str'),
    ldap=dict(type='str'),
    nextserver=dict(type='str'),
    filename32=dict(type='str'),
    filename64=dict(type='str'),
    filename32arm=dict(type='str'),
    filename64arm=dict(type='str'),
    uefihttpboot=dict(type='str'),
    numberoptions=dict(type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
)

DHCP_STATIC_REQUIRED_ONE_OF = [
    ('name', 'macaddr'),
]


class PFSenseDHCPStaticModule(PFSenseModuleBase):
    """ module managing pfsense dhcp static configuration """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DHCP_STATIC_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDHCPStaticModule, self).__init__(module, pfsense)
        self.name = "pfsense_dhcp_static"
        self.dhcpd = self.pfsense.get_element('dhcpd')
        self.root_elt = None
        self.staticmaps = None

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """

        params = self.params

        if re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', params['macaddr']) is None:
            self.module.fail_json(msg='A valid MAC address must be specified.')

        if params['netif'] is not None:
            self.pfsense.parse_interface(params['netif'])

        # find staticmaps and determine interface
        self._find_staticmaps(params['netif'])

        if params['ipaddr'] is not None:
            addr = ip_address(u'{0}'.format(params['ipaddr']))
            if addr not in self.network:
                self.module.fail_json(msg='The IP address must lie in the {0} subnet.'.format(self.netif))

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj
        # client identifier
        self._get_ansible_param(obj, 'name', fname='cid', force=True)

        if params['state'] == 'present':

            self._get_ansible_param(obj, 'macaddr', fname='mac', force=True)
            # Forced options
            for option in ['ipaddr', 'hostname', 'descr', 'filename',
                           'rootpath', 'defaultleasetime', 'maxleasetime',
                           'gateway', 'domain', 'domainsearchlist',
                           'ddnsdomain', 'ddnsdomainprimary', 'ddnsdomainsecondary',
                           'ddnsdomainkeyname', 'ddnsdomainkeyalgorithm', 'ddnsdomainkey',
                           'tftp', 'ldap', 'nextserver', 'filename32', 'filename64',
                           'filename32arm', 'filename64arm', 'uefihttpboot', 'numberoptions']:
                self._get_ansible_param(obj, option, force=True)
            # Non-forced options
            for option in ['winsserver', 'dnsserver', 'ntpserver']:
                self._get_ansible_param(obj, option)
            # Defaulted options
            self._get_ansible_param(obj, 'ddnsdomainkeyalgorithm', force_value='hmac-md5', force=True)

        return obj

    ##############################
    # XML processing
    #
    def _is_valid_netif(self, netif):
        for nic in self.pfsense.interfaces:
            if nic.tag == netif:
                if nic.find('ipaddr') is not None:
                    ipaddr = nic.find('ipaddr').text
                    if ipaddr is not None:
                        if nic.find('subnet') is not None:
                            subnet = int(nic.find('subnet').text)
                            if subnet < 31:
                                self.network = ip_network(u'{0}/{1}'.format(ipaddr, subnet), strict=False)
                                return True
        return False

    def _find_staticmaps(self, netif=None):
        for e in self.dhcpd:
            if netif is None or e.tag == netif:
                if e.find('enable') is not None:
                    if self._is_valid_netif(e.tag):
                        if self.root_elt is not None:
                            self.module.fail_json(msg='Multiple DHCP servers enabled and no netif specified')
                        self.root_elt = e
                        self.netif = e.tag
                        self.staticmaps = self.root_elt.findall('staticmap')
                        if netif is not None:
                            break

        if self.root_elt is None:
            if netif is None:
                self.module.fail_json(msg="No DHCP configuration")
            else:
                self.module.fail_json(msg="No DHCP configuration found for netif='{0}'".format(netif))

    def _find_target(self):
        if self.params['name'] is not None and self.params['macaddr'] is not None:
            result = self.root_elt.findall("staticmap[cid='{0}'][mac='{1}']".format(self.params['name'], self.params['macaddr']))
        elif self.params['name'] is not None:
            result = self.root_elt.findall("staticmap[cid='{0}']".format(self.params['name']))
        else:
            result = self.root_elt.findall("staticmap[mac='{0}']".format(self.params['macaddr']))

        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple static maps for cid {0}.'.format(self.obj['cid']))
        else:
            return None

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('staticmap')

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        obj = self.obj

        self.diff['after'] = obj
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.root_elt.append(self.target_elt)
        # Reset static map list
        self.staticmaps = self.root_elt.findall('staticmap')

    def _copy_and_update_target(self):
        """ update the XML target_elt """

        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before

        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)

        return (before, changed)

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'" + self.obj['cid'] + "'"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.params, 'macaddr')
            values += self.format_cli_field(self.params, 'ipaddr')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'macaddr', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'ipaddr', add_comma=(values))
        return values

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell("""
            require_once("util.inc");
            require_once("services.inc");
            $retvaldhcp = services_dhcpd_configure();
            if ($retvaldhcp == 0) {
              clear_subsystem_dirty('staticmaps');
            }""")

    def _pre_remove_target_elt(self):
        self.diff['after'] = {}
        if self.target_elt is not None:
            self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)

            self.staticmaps.remove(self.target_elt)
        else:
            self.diff['before'] = {}


def main():
    module = AnsibleModule(
        argument_spec=DHCP_STATIC_ARGUMENT_SPEC,
        required_one_of=DHCP_STATIC_REQUIRED_ONE_OF,
        supports_check_mode=True)

    pfmodule = PFSenseDHCPStaticModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
