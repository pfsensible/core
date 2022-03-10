# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Chris Morton, cosmo@cosmo.2y.net
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import re
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

HAPROXY_FRONTEND_SERVER_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    frontend=dict(required=True, type='str'),
    extaddr=dict(required=True, type='str'),
    extaddr_port=dict(required=True, type='int'),
    extaddr_ssl=dict(required=True, type='str'),
)


class PFSenseHaproxyFrontendServerModule(PFSenseModuleBase):
    """ module managing pfsense haproxy frontends """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return HAPROXY_FRONTEND_SERVER_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseHaproxyFrontendServerModule, self).__init__(module, pfsense)
        self.name = "pfsense_haproxy_frontend_server"
        self.root_elt = None
        self.obj = dict()

        pkgs_elt = self.pfsense.get_element('installedpackages')
        self.haproxy = pkgs_elt.find('haproxy') if pkgs_elt is not None else None
        self.frontends = self.haproxy.find('ha_backends') if self.haproxy is not None else None
        if self.frontends is None:
            self.module.fail_json(msg='Unable to find frontends (ha_backends) XML configuration entry. Are you sure haproxy is installed ?')

        self.frontend = None

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a frontend dict from module params """
        obj = dict()
        self._get_ansible_param(obj, 'extaddr')
        self._get_ansible_param(obj, 'extaddr_port')
        self._get_ansible_param(obj, 'extaddr_ssl')
        obj['name'] = "'{0}_{1}'".format(self.params['extaddr'],self.params['extaddr_port'])
            
        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """

        #get the frontend
        self.frontend = self._find_frontend(self.params['frontend'])
        if self.frontend is None:
            self.module.fail_json(msg="The frontend named '{0}' does not exist".format(self.params['frontend']))

        #setup the a_extaddr if we dont hav eit
        self.root_elt = self.frontend.find('a_extaddr')
        if self.root_elt is None:
            self.root_elt = self.pfsense.new_element('a_extaddr')
            self.frontend.append(self.root_elt)

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        server_elt = self.pfsense.new_element('item')
        return server_elt

    def _find_frontend(self, name):
        """ return the target frontend_elt if found """
        for item_elt in self.frontends:
            if item_elt.tag != 'item':
                continue
            name_elt = item_elt.find('name')
            if name_elt is not None and name_elt.text == name:
                return item_elt
        return None

    def _find_target(self):
        """ find the XML target_elt """
        for item_elt in self.root_elt:
            if item_elt.tag != 'item':
                continue
            name_elt = item_elt.find('name')
            print(name_elt)
            if name_elt is not None and name_elt.text == self.obj['name']:
                return item_elt
        return None

    def _get_next_id(self):
        """ get next free haproxy id  """
        max_id = 99
        id_elts = self.haproxy.findall('.//id')
        for id_elt in id_elts:
            if id_elt.text is None:
                continue
            ha_id = int(id_elt.text)
            if ha_id > max_id:
                max_id = ha_id
        return str(max_id + 1)

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload haproxy """
        return self.pfsense.phpshell('''require_once("haproxy/haproxy.inc");
$result = haproxy_check_and_run($savemsg, true); if ($result) unlink_if_exists($d_haproxyconfdirty_path);''')

    ##############################
    # Logging
    #
    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.params, 'extaddr')
            values += self.format_cli_field(self.params, 'extaddr_port')
            values += self.format_cli_field(self.params, 'extaddr_ssl')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'extaddr', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'extaddr_port', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'extaddr_ssl', add_comma=(values))
        return values

    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}_{1}'".format(self.obj['extaddr'],self.obj['extaddr_port'])
