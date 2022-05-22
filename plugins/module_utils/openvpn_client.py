# -*- coding: utf-8 -*-

# Copyright: (c) 2020-2021, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2020, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import base64
import re

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

OPENVPN_CLIENT_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    mode=dict(default='p2p_tls', required=False, choices=['p2p_tls', 'p2p_shared_key']),
    authmode=dict(default=list(), required=False, type='list', elements='str'),
    state=dict(default='present', choices=['present', 'absent']),
    custom_options=dict(default=None, required=False, type='str'),
    disable=dict(default=False, required=False, type='bool'),
    interface=dict(default='wan', required=False, type='str'),
    server_addr=dict(required=True, type='str'),
    server_port=dict(default=1194, required=False, type='int'),
    protocol=dict(default='UDP4', required=False, choices=['UDP4', 'TCP4']),
    dev_mode=dict(default='tun', required=False, choices=['tun', 'tap']),
    tls=dict(required=False, type='str'),
    ca=dict(required=False, type='str'),
    crl=dict(required=False, type='str'),
    cert=dict(required=False, type='str'),
    cert_depth=dict(default=1, required=False, type='int'),
    strictuserdn=dict(default=False, required=False, type='bool'),
    shared_key=dict(required=False, type='str', no_log=True),
    dh_length=dict(default=2048, required=False, type='int'),
    ecdh_curve=dict(default='none', required=False, choices=['none', 'prime256v1', 'secp384r1', 'secp521r1']),
    ncp_enable=dict(default=False, required=False, type='bool'),
    # ncp_ciphers=dict(default=list('AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'), required=False,
    #                  choices=['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'], type='list', elements='str'),
    data_ciphers=dict(default=None, required=False, choices=['AES-256-CBC', 'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'], type='list', elements='str'),
    data_ciphers_fallback=dict(default='AES-256-CBC', required=False, choices=['AES-256-CBC', 'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305']),
    digest=dict(default='SHA256', required=False, choices=['SHA256', 'SHA1']),
    tunnel_network=dict(default='', required=False, type='str'),
    tunnel_networkv6=dict(default='', required=False, type='str'),
    remote_network=dict(default='', required=False, type='str'),
    remote_networkv6=dict(default='', required=False, type='str'),
    gwredir=dict(default=False, required=False, type='bool'),
    gwredir6=dict(default=False, required=False, type='bool'),
    maxclients=dict(default=None, required=False, type='int'),
    compression=dict(default='adaptive', required=False, choices=['adaptive', '']),
    compression_push=dict(default=False, required=False, type='bool'),
    passtos=dict(default=False, required=False, type='bool'),
    client2client=dict(default=False, required=False, type='bool'),
    dynamic_ip=dict(default=False, required=False, type='bool'),
    topology=dict(default='subnet', required=False, choices=['net30', 'subnet']),
    dns_domain=dict(default='', required=False, type='str'),
    dns_client1=dict(default='', required=False, type='str'),
    dns_client2=dict(default='', required=False, type='str'),
    dns_client3=dict(default='', required=False, type='str'),
    dns_client4=dict(default='', required=False, type='str'),
    push_register_dns=dict(default=False, required=False, type='bool'),
    create_gw=dict(default='both', required=False, choices=['both']),
    verbosity_level=dict(default=3, required=False, type='int'),
)

OPENVPN_CLIENT_REQUIRED_IF = [
    ['mode', 'p2p_tls', ['ca']],
    ['mode', 'p2p_shared_key', ['shared_key']],
]

OPENVPN_CLIENT_PHP_COMMAND_PREFIX = """
require_once('openvpn.inc');
init_config_arr(array('openvpn', 'openvpn-client'));
$a = &$config['openvpn']['openvpn-client'];
$ovpn = $a[{idx}];
"""

OPENVPN_CLIENT_PHP_COMMAND_SET = OPENVPN_CLIENT_PHP_COMMAND_PREFIX + """
openvpn_resync('client',$ovpn);
"""

OPENVPN_CLIENT_PHP_COMMAND_DEL = OPENVPN_CLIENT_PHP_COMMAND_PREFIX + """
openvpn_delete($a[{idx}]);
unset($a[{idx}]);
openvpn_resync('client',$ovpn);
"""


class PFSenseOpenVPNClientModule(PFSenseModuleBase):
    """ module managing pfSense OpenVPN configuration """

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseOpenVPNClientModule, self).__init__(module, pfsense)
        self.name = "pfsense_openvpn"
        self.root_elt = self.pfsense.get_element('openvpn')
        self.obj = dict()

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return dict from module params """
        obj = dict()
        obj['description'] = self.params['name']
        if self.params['state'] == 'present':
            obj['custom_options'] = self.params['custom_options']
            self._get_ansible_param_bool(obj, 'disable')
            self._get_ansible_param_bool(obj, 'strictuserdn')
            obj['mode'] = self.params['mode']
            obj['dev_mode'] = self.params['dev_mode']
            obj['interface'] = self.params['interface']
            obj['protocol'] = self.params['protocol']
            obj['server_addr'] = self.params['server_addr']
            obj['server_port'] = str(self.params['server_port'])
            self._get_ansible_param(obj, 'maxclients')
            obj['verbosity_level'] = str(self.params['verbosity_level'])
            obj['data_ciphers_fallback'] = self.params['data_ciphers_fallback']
            obj['data_ciphers'] = ",".join(self.params['data_ciphers'])
            self._get_ansible_param_bool(obj, 'ncp_enable', 'enabled')
            self._get_ansible_param_bool(obj, 'gwredir')
            self._get_ansible_param_bool(obj, 'gwredirr6')
            self._get_ansible_param_bool(obj, 'compression_push')
            self._get_ansible_param_bool(obj, 'passtos')
            self._get_ansible_param_bool(obj, 'client2client')
            self._get_ansible_param_bool(obj, 'dynamic_ip')
            self._get_ansible_param_bool(obj, 'push_register_dns')
            obj['digest'] = self.params['digest']
            obj['tunnel_network'] = self.params['tunnel_network']
            obj['tunnel_networkv6'] = self.params['tunnel_networkv6']
            obj['remote_network'] = self.params['remote_network']
            obj['remote_networkv6'] = self.params['remote_networkv6']
            obj['compression'] = self.params['compression']
            obj['topology'] = self.params['topology']
            obj['create_gw'] = self.params['create_gw']

            if 'user' in self.params['mode']:
                obj['authmode'] = ",".join(self.params['authmode'])

            if 'tls' in self.params['mode']:
                # Find the caref id for the named CA
                if self.params is not None:
                    ca_elt = self.pfsense.find_ca_elt(self.params['ca'])
                    if ca_elt is None:
                        self.module.fail_json(msg='%s is not a valid certificate authority' % (self.params['ca']))
                    obj['caref'] = ca_elt.find('refid').text
                # Find the crlref id for the named CRL if any
                if self.params['crl'] is not None:
                    crl_elt = self.pfsense.find_crl_elt(self.params['crl'])
                    if crl_elt is None:
                        self.module.fail_json(msg='%s is not a valid certificate revocation list' % (self.params['crl']))
                    obj['crlref'] = crl_elt.find('refid').text
                else:
                    obj['crlref'] = ''
                # Find the certref id for the named certificate if any
                if self.params['cert'] is not None:
                    cert_elt = self.pfsense.find_cert_elt(self.params['cert'])
                    if cert_elt is None:
                        self.module.fail_json(msg='%s is not a valid certificate' % (self.params['cert']))
                    obj['certref'] = cert_elt.find('refid').text

            if self.params['mode'] == 'p2p_shared_key':
                obj['shared_key'] = self.params['shared_key']

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        # check name
        self.pfsense.validate_string(params['name'], 'openvpn')

        # Check auth clients
        if len(params['authmode']) > 0:
            system = self.pfsense.get_element('system')
            for authsrv in params['authmode']:
                if len(system.findall("authclient[name='{0}']".format(authsrv))) == 0:
                    self.module.fail_json(msg='Cannot find authentication client {0}.'.format(authsrv))

        # validate key
        if params['shared_key'] is not None:
            key = params['shared_key']
            lines = key.splitlines()
            if lines[0] == '-----BEGIN OpenVPN Static key V1-----' and lines[-1] == '-----END OpenVPN Static key V1-----':
                params['shared_key'] = base64.b64encode(key.encode()).decode()
            elif not re.match('LS0tLS1CRUdJTiBPcGVuVlBOIFN0YXRpYyBrZXkgVjEtLS0tLQ', key):
                self.module.fail_json(msg='Could not recognize key format: %s' % (key))

    def _nextvpnid(self):
        """ find next available vpnid """
        vpnid = 1
        while len(self.root_elt.findall("*[vpnid='{0}']".format(vpnid))) != 0:
            vpnid += 1
        return str(vpnid)

    ##############################
    # XML processing
    #
    def _find_openvpn_client(self, value, field='description'):
        """ return openvpn-client element """
        i = 0
        for elt in self.root_elt:
            field_elt = elt.find(field)
            if field_elt is not None and field_elt.text == value:
                return (elt, i)
            i += 1
        return (None, -1)

    def _find_last_openvpn_idx(self):
        i = 0
        for elt in self.root_elt:
            i += 1
        return i

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        if self._remove_deleted_params():
            changed = True

        self.diff['before'] = before
        if changed:
            self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
            self.result['changed'] = True
        else:
            self.diff['after'] = self.obj

        return (before, changed)

    def _create_target(self):
        """ create the XML target_elt """
        target_elt = self.pfsense.new_element('openvpn-client')
        self.obj['vpnid'] = self._nextvpnid()
        self.diff['before'] = ''
        self.diff['after'] = self.obj
        self.result['changed'] = True
        self.idx = self._find_last_openvpn_idx()
        return target_elt

    def _find_target(self):
        """ find the XML target_elt """
        (target_elt, self.idx) = self._find_openvpn_client(self.obj['description'])
        return target_elt

    def _remove_target_elt(self):
        """ delete target_elt from xml """
        super(PFSenseOpenVPNClientModule, self)._remove_target_elt()
        self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)

    ##############################
    # run
    #
    def _remove(self):
        """ delete obj """
        self.diff['after'] = ''
        self.diff['before'] = ''
        super(PFSenseOpenVPNClientModule, self)._remove()
        return self.pfsense.phpshell(OPENVPN_CLIENT_PHP_COMMAND_DEL.format(idx=self.idx))

    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell(OPENVPN_CLIENT_PHP_COMMAND_SET.format(idx=self.idx))

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'" + self.obj['description'] + "'"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.obj, 'description')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'description', add_comma=(values))
        return values
