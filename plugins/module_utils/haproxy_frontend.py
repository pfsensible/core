# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import re
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

HAPROXY_FRONTEND_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    mode=dict(default='active', choices=['active', 'disabled']),
    name=dict(required=True, type='str'),
    frontend_type=dict(default='http', choices=['http', 'ssl', 'tcp']),
    httpclose=dict(default='http-keep-alive', choices=['http-keep-alive', 'http-tunnel', 'httpclose', 'http-server-close', 'forceclose']),
    ssloffloadcert=dict(required=False, type='str'),
    ssloffloadacl_an=dict(required=False, type='bool'),
    ha_acls=dict(required=False, type='str'),
    ha_certificates=dict(required=False, type='str'),
    clientcert_ca=dict(required=False, type='str'),
    clientcert_crl=dict(required=False, type='str'),
    a_actionitems=dict(required=False, type='str'),
    a_errorfiles=dict(required=False, type='str'),
)


class PFSenseHaproxyFrontendModule(PFSenseModuleBase):
    """ module managing pfsense haproxy frontends """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return HAPROXY_FRONTEND_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseHaproxyFrontendModule, self).__init__(module, pfsense)
        self.name = "pfsense_haproxy_frontend"
        self.obj = dict()

        pkgs_elt = self.pfsense.get_element('installedpackages')
        self.haproxy = pkgs_elt.find('haproxy') if pkgs_elt is not None else None
        self.root_elt = self.haproxy.find('ha_pools') if self.haproxy is not None else None
        if self.root_elt is None:
            self.module.fail_json(msg='Unable to find frontends XML configuration entry. Are you sure haproxy is installed ?')

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a frontend dict from module params """
        obj = dict()
        obj['name'] = self.params['name']
        if params['state'] == 'present':
            obj['status'] = self.params['mode']

            self._get_ansible_param(obj, 'frontend_type', fname='type', force=True)
            self._get_ansible_param(obj, 'httpclose', force=True)
            self._get_ansible_param(obj, 'ssloffloadcert', force=True)
            self._get_ansible_param(obj, 'ha_acls', force=True)
            self._get_ansible_param(obj, 'ha_certificates', force=True)
            self._get_ansible_param(obj, 'clientcert_ca', force=True)
            self._get_ansible_param(obj, 'clientcert_crl', force=True)
            self._get_ansible_param_bool(obj, 'ssloffloadacl_an', force=True)
            self._get_ansible_param(obj, 'a_actionitems', force=True)
            self._get_ansible_param(obj, 'a_errorfiles', force=True)

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        # check name
        if re.search(r'[^a-zA-Z0-9\.\-_]', self.params['name']) is not None:
            self.module.fail_json(msg="The field 'name' contains invalid characters.")

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        server_elt = self.pfsense.new_element('item')
        self.obj['id'] = self._get_next_id()
        return server_elt

    def _find_target(self):
        """ find the XML target_elt """
        for item_elt in self.root_elt:
            if item_elt.tag != 'item':
                continue
            name_elt = item_elt.find('name')
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
            values += self.format_cli_field(self.params, 'frontend_type')
            values += self.format_cli_field(self.params, 'httpclose')
            values += self.format_cli_field(self.params, 'ssloffloadcert')
            values += self.format_cli_field(self.params, 'ssloffloadacl_an', fvalue=self.fvalue_bool)
            values += self.format_cli_field(self.params, 'ha_acls')
            values += self.format_cli_field(self.params, 'ha_certificates')
            values += self.format_cli_field(self.params, 'clientcert_ca')
            values += self.format_cli_field(self.params, 'clientcert_crl')
            values += self.format_cli_field(self.params, 'a_actionitems')
            values += self.format_cli_field(self.params, 'a_errorfiles')
        else:
            for param in ['type', 'ssloffloadacl_an']:
                if param in before and before[param] == '':
                    before[param] = None
            values += self.format_updated_cli_field(self.obj, before, 'frontend_type', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'httpclose', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'ssloffloadcert', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'ssloffloadacl_an', add_comma=(values), fvalue=self.fvalue_bool)
            values += self.format_updated_cli_field(self.obj, before, 'ha_acls', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'ha_certificates', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'clientcert_ca', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'clientcert_crl', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'a_actionitems', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'a_errorfiles', add_comma=(values))
        return values

    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}'".format(self.obj['name'])
