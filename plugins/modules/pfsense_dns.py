# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Chris Liu <chris.liu.hk@icloud.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# TODO: advance page of DNS and access control is not done here
# TODO: alias for DNS record

from __future__ import absolute_import, division, print_function
import base64
import copy
__metaclass__ = type
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase
from ansible.module_utils.basic import AnsibleModule

DNS_DOMAIN_OVERRIDE_SPEC = dict(
    domain=dict(required=True, type='str'),
    ip=dict(required=True, type='str'),
    descr=dict(default='', type='str'),
    tls_hostname=dict(default='', type='str'),
    forward_tls_upstream=dict(default='', type='str'),  
)

DNS_HOST_ALIAS_SPEC = dict(
    host=dict(required=True, type='str'),
    domain=dict(required=True, type='str'),
    description=dict(required=True, type='str'),
)

DNS_HOST_SPEC = dict(
    host=dict(required=True, type='str'),
    domain=dict(required=True, type='str'),
    ip=dict(required=True, type='str'),
    descr=dict(default="", type='str'),
    aliases=dict(default=[], type='list', elements='dict', options=DNS_HOST_ALIAS_SPEC),
)

dns_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),

    list_active_interface_descr=dict(default=["all"], type='list', elements='str'),
    list_outgoing_interface_descr=dict(default=["all"], type='list', elements='str'),
    custom_options=dict(default="", type='str'),
    hideidentity=dict(default=True, type='bool'),
    hideversion=dict(default=True, type='bool'),
    dnssecstripped=dict(default=True, type='bool'),
    port=dict(default=53, type='int'),
    tlsport=dict(default=853, type='int'),
    sslcertdescr=dict(default="", type='str'), #need transform
    forwarding=dict(default=False, type='bool'),
    system_domain_local_zone_type=dict(default='transparent', choice=['deny', 'refuse', 'static', 'transparent', 'typetransparent', 'redirect', 'inform', 'inform_deny', 'inform_deny']),
    regdhcp=dict(default=False, type='bool'),
    regdhcpstatic=dict(default=False, type='bool'),
    regovpnclients=dict(default=False, type='bool'),
    enablessl=dict(default=False, type='bool'),
    dnssec=dict(default=False, type='bool'),
    forward_tls_upstream=dict(default=False, type='bool'),
    hosts=dict(default=[], type='list', elements='dict', options=DNS_HOST_SPEC),
    domainoverrides=dict(default=[], type='list', elements='dict', options=DNS_DOMAIN_OVERRIDE_SPEC)
)

dns_REQUIRED_IF = []


class PFSenseDNSModule(PFSenseModuleBase):
    """ module managing pfsense dnss """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return dns_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDNSModule, self).__init__(module, pfsense)
        self.name = "pfsense_dns"
        self.root_elt = self.pfsense.get_element('unbound')
        self.obj = dict()
        self.interface_elt = None
        self.dynamic = False

        if self.root_elt is None:
            self.root_elt = self.pfsense.new_element('unbound')
            self.pfsense.root.append(self.root_elt)
    
    def get_interface_by_display_name(self, if_descr:str):
        if if_descr.lower() == "all":
            return "all"
        else:
            return self.pfsense.get_interface_by_display_name(if_descr)

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()

        if params["state"] == "present":

            obj["enable"] = ""
            obj["active_interface"] = ",".join(self.get_interface_by_display_name(x) for x in params["list_active_interface_descr"])
            obj["outgoing_interface"] = ",".join(self.get_interface_by_display_name(x) for x in params["list_outgoing_interface_descr"])
            obj["custom_options"] = base64.b64encode(bytes(params['custom_options'],'utf-8')).decode()
            self._get_ansible_param_bool(obj, "hideidentity", value="")
            self._get_ansible_param_bool(obj, "hideversion", value="")
            self._get_ansible_param_bool(obj, "dnssecstripped", value="")
            self._get_ansible_param(obj, "port")
            self._get_ansible_param(obj, "tlsport")
            if params["sslcertdescr"]:
                obj["sslcertref"] = self.pfsense.find_cert_elt(params["sslcertdescr"]).find("refid").text
            self._get_ansible_param_bool(obj, "forwarding", value="")
            self._get_ansible_param(obj, "system_domain_local_zone_type")
            self._get_ansible_param_bool(obj, "regdhcp", value="")
            self._get_ansible_param_bool(obj, "regdhcpstatic", value="")
            self._get_ansible_param_bool(obj, "regovpnclients", value="")
            self._get_ansible_param_bool(obj, "enablessl", value="")
            self._get_ansible_param_bool(obj, "dnssec", value="")
            self._get_ansible_param_bool(obj, "forward_tls_upstream", value="")
            self._get_ansible_param(obj, "hosts")
            self._get_ansible_param(obj, "domainoverrides")

            if obj["active_interface"] != "all":
                obj["active_interface"] += ",lo0"

            # wrap <item> to all hosts.alias
            for host in obj["hosts"]:
                if host["aliases"]:
                    tmp_aliases = host["aliases"]
                    host["aliases"] = {
                        "item": tmp_aliases
                    }

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params["sslcertdescr"] and not self.pfsense.find_cert_elt(params["sslcertdescr"]):
            self.module.fail_json(msg=f'sslcertdescr, {params["sslcertdescr"]} is not a valid description of cert')
        
        for host in params["hosts"]:
            if not self.pfsense.is_ipv4_address(host["ip"]):
                self.module.fail_json(msg=f'ip, {host["ip"]} is not a ipv4 address')

        for if_descr in params["list_active_interface_descr"]+params["list_outgoing_interface_descr"]:
            if not self.pfsense.is_interface_display_name(if_descr) and if_descr.lower()!="all":
                self.module.fail_json(msg=f'if_descr, {if_descr}, is not exist')


    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        return self.root_elt

    def _find_target(self):
        """ find the XML target_elt """
        return self.root_elt            

    def _get_params_to_remove(self):
        """ returns the list of params to remove if they are not set """
        if self.params["state"] == "absent":
            return ["enable"]
        else:
            return []

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell('''
require_once("unbound.inc");
require_once("pfsense-utils.inc");
require_once("system.inc");

services_unbound_configure();
system_resolvconf_generate();
system_dhcpleases_configure();
clear_subsystem_dirty("unbound");
''')

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return self.name

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        values += self.format_updated_cli_field(self.obj, before, 'enable', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'active_interface', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'outgoing_interface', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'custom_options', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'hideidentity', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'hideversion', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'dnssecstripped', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'port', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'tlsport', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'sslcertref', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'forwarding', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'system_domain_local_zone_type', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'regdhcp', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, before, 'regdhcpstatic', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        
        # todo: hosts and domainoverrides is not logged
        return values



def main():
    module = AnsibleModule(
        argument_spec=dns_ARGUMENT_SPEC,
        required_if=dns_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseDNSModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
