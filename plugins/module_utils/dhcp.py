# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

DHCP_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    interface=dict(required=True, type='str'),
    enable=dict(required=False, type='bool'),
    range_from=dict(default=None, required=True, type='str'),
    range_to=  dict(default=None, required=True, type='str'),
    failover_peerip = dict(default=None, type='str'),
    defaultleasetime = dict(default=None, type='int'),
    maxleasetime = dict(default=None, type='int'),
    netmask = dict(default=None, type='str'),
    gateway = dict(default=None, type='str'),
    domain = dict(default=None, type='str'),
    domainsearchlist = dict(default=None, type='str'),
    ddnsdomain = dict(default=None, type='str'),
    ddnsdomainprimary = dict(default=None, type='str'),
    ddnsdomainsecondary = dict(default=None, type='str'),
    ddnsdomainkeyname = dict(default=None, type='str'),
    ddnsdomainkeyalgorithm = dict(default="hmac-md5", type='str'),
    ddnsdomainkey = dict(default=None, type='str'),
    mac_allow = dict(default=None, type='str'),
    mac_deny = dict(default=None, type='str'),
    ddnsclientupdates = dict(default="allow", type='str'),
    tftp = dict(default=None, type='str'),
    ldap = dict(default=None, type='str'),
    nextserver = dict(default=None, type='str'),
    filename = dict(default=None, type='str'),
    filename32 = dict(default=None, type='str'),
    filename64 = dict(default=None, type='str'),
    filename32arm = dict(default=None, type='str'),
    filename64arm = dict(default=None, type='str'),
    rootpath = dict(default=None, type='str'),
    numberoptions = dict(default=None, type='str')
)


class PFSenseDhcpModule(PFSenseModuleBase):
    """ module managing pfsense DHCP """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DHCP_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDhcpModule, self).__init__(module, pfsense)
        self.name = "pfsense_dhcp"
        self.root_elt = self.pfsense.get_element('dhcpd')
        self.obj = dict()

        if self.root_elt is None:
            self.root_elt = self.pfsense.new_element('dhcpd')
            self.pfsense.root.append(self.root_elt)

        # get interfaces on which DHCP can be set
        get_interface_cmd = (
            'require_once("/etc/inc/interfaces.inc");'
            'echo json_encode(get_configured_interface_with_descr());')

        self.interfaces = self.pfsense.php(get_interface_cmd)
        # Reverse dictionary mapping
        self.interfaces = {v: k for k, v in self.interfaces.items()}
    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        # get target interface
        self.target_elt = self._get_interface_elt_by_port(self.interfaces[params['interface']])
        if params['state'] == 'present':

            obj['range'] = {
                'from': params['range_from'],
                'to'  : params['range_to']
            }

            # TODO: probably need some processing here
            if params['enable']:
                obj['enable']             = ''

            obj['failover_peerip']        = params['failover_peerip']       
            obj['defaultleasetime']       = params['defaultleasetime']      
            obj['maxleasetime']           = params['maxleasetime']          
            obj['netmask']                = params['netmask']               
            obj['gateway']                = params['gateway']               
            obj['domain']                 = params['domain']                
            obj['domainsearchlist']       = params['domainsearchlist']      
            obj['ddnsdomain']             = params['ddnsdomain']            
            obj['ddnsdomainprimary']      = params['ddnsdomainprimary']     
            obj['ddnsdomainsecondary']    = params['ddnsdomainsecondary']   
            obj['ddnsdomainkeyname']      = params['ddnsdomainkeyname']     
            obj['ddnsdomainkeyalgorithm'] = params['ddnsdomainkeyalgorithm']
            obj['ddnsdomainkey']          = params['ddnsdomainkey']         
            obj['mac_allow']              = params['mac_allow']             
            obj['mac_deny']               = params['mac_deny']              
            obj['ddnsclientupdates']      = params['ddnsclientupdates']     
            obj['tftp']                   = params['tftp']                  
            obj['ldap']                   = params['ldap']                  
            obj['nextserver']             = params['nextserver']            
            obj['filename']               = params['filename']              
            obj['filename32']             = params['filename32']            
            obj['filename64']             = params['filename64']            
            obj['filename32arm']          = params['filename32arm']         
            obj['filename64arm']          = params['filename64arm']         
            obj['rootpath']               = params['rootpath']              
            obj['numberoptions']          = params['numberoptions']         

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        # check interface
        if params['interface'] not in self.interfaces:
            # check with assign or friendly name
            interface = self.pfsense.get_interface_port_by_display_name(params['interface'])
            if interface is None:
                interface = self.pfsense.get_interface_port(params['interface'])

            if interface is None or interface not in self.interfaces:
                self.module.fail_json(msg='DHCP can\'t be set on interface {0}'.format(params['interface']))

        # TODO: more



    ##############################
    # XML processing
    #
    def _copy_and_add_target(self):
        """ create the XML target_elt """
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)

        if self._remove_deleted_params():
            changed = True

        return (before, changed)

    @staticmethod
    def _get_params_to_remove():
        """ returns the list of params to remove if they are not set """
        params = ['enable', ]
        return params

    def _get_interface_elt_by_port(self, interface_port):
        """ return pfsense interface_elt """
        for iface in self.root_elt:
            if iface.tag.strip().lower() == interface_port.lower():
                return iface
        return None

    def _create_target(self):
        """ create the XML target_elt """
        interface = self.interfaces[self.params['interface']]
        i = int(interface.replace("opt", ""))
        interface_elt = self.pfsense.new_element(interface)
        self.root_elt.insert(i, interface_elt)
        return interface_elt

    def _find_target(self):
        """ find the XML target_elt """
        return self.target_elt

    ##############################
    # run
    #
    def get_update_cmds(self):
        """ build and return php commands to setup interfaces """
        cmd = 'services_dhcpdv4_configure();\n'
        return cmd

    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell(self.get_update_cmds())

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'dhcpd_{0}'".format(self.params['interface'])

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.obj, 'descr')
            values += self.format_cli_field(self.obj, 'pcp', fname='priority')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'pcp', add_comma=(values), fname='priority')
            values += self.format_updated_cli_field(self.obj, before, 'descr', add_comma=(values))
        return values
