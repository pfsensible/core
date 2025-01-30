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
module: pfsense_ca
version_added: 0.1.0
short_description: Manage pfSense Certificate Authorities
description:
  >
    Manage pfSense Certificate Authorities
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name of the Certificate Authority
    required: true
    type: str
  state:
    description: State in which to leave the Certificate Authority
    default: present
    choices: [ "present", "absent" ]
    type: str
  trust:
    description: Add this Certificate Authority to the Operating System Trust Store. Defaults to false.
    type: bool
    version_added: 0.5.0
  randomserial:
    description:  Use random serial numbers when signing certifices. Defaults to false.
    type: bool
    version_added: 0.5.0
  certificate:
    description:
      >
        The certificate for the Certificate Authority.  This can be in PEM form or Base64
        encoded PEM as a single string (which is how pfSense stores it).
    type: str
  crl:
    description:
      >
        The Certificate Revocation List for the Certificate Authority.  This can be in PEM
        form or Base64 encoded PEM as a single string (which is how pfSense stores it).
    required: false
    type: str
  crlname:
    description:
      >
        The name of the CRL.  This will default to name + ' CRL'.  If multiple CRLs exist
        with this name, you must specify crlrefid.
    required: false
    type: str
    version_added: 0.5.0
  crlrefid:
    description: The refrence ID of the CRL.  This will default to a unique id based on time.
    required: false
    type: str
    version_added: 0.5.0
  key:
    description:
      >
        The private key for the Certificate Authority.  This can be in PEM form or Base64
        encoded PEM as a single string (which is how pfSense stores it).
    type: str
    version_added: 0.6.2
  serial:
    description: Number to be used as a sequential serial number for the next certificate to be signed by this CA.
    type: int
    version_added: 0.5.0
"""

EXAMPLES = """
- name: Add AD Certificate Authority
  pfsense_ca:
    name: AD CA
    certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGcXpDQ0E1T2dB...
    crl: |
      -----BEGIN X509 CRL-----
      MIICazCCAVMCAQEwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPTldSQSBPcGVu
      ...
      r0hUUy3w1trKtymlyhmd5XmYzINYp8p/Ws+boST+Fcw3chWTep/J8nKMeKESO0w=
      -----END X509 CRL-----
    state: present

- name: Remove AD Certificate Authority
  pfsense_ca:
    name: AD CA
    state: absent
"""

RETURN = """

"""

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

PFSENSE_CA_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    trust=dict(type='bool'),
    randomserial=dict(type='bool'),
    certificate=dict(type='str'),
    crl=dict(default=None, type='str'),
    crlname=dict(default=None, type='str'),
    crlrefid=dict(default=None, type='str'),
    key=dict(type='str', no_log=True),
    serial=dict(type='int'),
)


class PFSenseCAModule(PFSenseModuleBase):
    """ module managing pfsense certificate authorities """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return PFSENSE_CA_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseCAModule, self).__init__(module, pfsense)
        self.name = "pfsense_ca"
        self.root_elt = self.pfsense.root
        self.cas = self.pfsense.get_elements('ca')
        self.refresh_crls = False
        self.crl = None

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params['state'] == 'absent':
            return

        # TODO - Make sure certificate purpose includes CA
        cert = params['certificate']
        lines = cert.splitlines()
        if lines[0] == '-----BEGIN CERTIFICATE-----' and lines[-1] == '-----END CERTIFICATE-----':
            params['certificate'] = base64.b64encode(cert.encode()).decode()
        elif not re.match('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', cert):
            self.module.fail_json(msg='Could not recognize certificate format: %s' % (cert))

        if params['crl'] is not None:
            crl = params['crl']
            lines = crl.splitlines()
            if lines[0] == '-----BEGIN X509 CRL-----' and lines[-1] == '-----END X509 CRL-----':
                params['crl'] = base64.b64encode(crl.encode()).decode()
            elif not re.match('LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0t', crl):
                self.module.fail_json(msg='Could not recognize CRL format: %s' % (crl))

        if params['key'] is not None:
            ca_key = params['key']
            lines = ca_key.splitlines()
            if lines[0] == '-----BEGIN PRIVATE KEY-----' and lines[-1] == '-----END PRIVATE KEY-----':
                params['key'] = base64.b64encode(ca_key.encode()).decode()
            elif not re.match('LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t', ca_key):
                self.module.fail_json(msg='Could not recognize CA key format: %s' % (ca_key))

        if params['serial'] is not None:
            if int(params['serial']) < 1:
                self.module.fail_json(msg='serial must be greater than 0')

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        obj['descr'] = params['name']
        if params['state'] == 'present':
            if 'certificate' in params and params['certificate'] is not None:
                obj['crt'] = params['certificate']
            if params['crl'] is not None:
                self.crl = {}
                self.crl['method'] = 'existing'
                self.crl['text'] = params['crl']
                self._get_ansible_param(self.crl, 'crlname', fname='descr', force=True, force_value=obj['descr'] + ' CRL')
                self._get_ansible_param(self.crl, 'crlrefid', fname='refid')
            if params['key'] is not None:
                obj['prv'] = params['key']

        self._get_ansible_param_bool(obj, 'trust', value='enabled', value_false='disabled')
        self._get_ansible_param_bool(obj, 'randomserial', value='enabled', value_false='disabled')
        self._get_ansible_param(obj, 'serial')

        return obj

    ##############################
    # XML processing
    #
    def _find_target(self):
        result = self.root_elt.findall("ca[descr='{0}']".format(self.obj['descr']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple certificate authorities for name {0}.'.format(self.obj['descr']))
        else:
            return None

    def _find_this_ca_index(self):
        return self.cas.index(self.target_elt)

    def _find_last_ca_index(self):
        if len(self.cas):
            return list(self.root_elt).index(self.cas[len(self.cas) - 1])
        else:
            return len(list(self.root_elt))

    def _find_crl_for_ca(self, caref):
        result = self.root_elt.findall("crl[caref='{0}']".format(caref))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple CRLs for caref {0}, you must specify crlname or crlrefid.'.format(caref))
        else:
            return None

    def _find_crl_by_name(self, crlname):
        result = self.root_elt.findall("crl[descr='{0}']".format(crlname))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple CRLs for name {0}, you must specify crlrefid.'.format(crlname))
        else:
            return None

    def _find_crl_by_refid(self, crlrefid):
        result = self.root_elt.findall("crl[refid='{0}']".format(crlrefid))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple CRLs for refid {0}.  This is an unsupported condition'.format(crlrefid))
        else:
            return None

    def _create_target(self):
        """ create the XML target_elt """
        elt = self.pfsense.new_element('ca')
        # We need this later in _copy_and_add_target()
        self.obj['refid'] = self.pfsense.uniqid()
        elt.append(self.pfsense.new_element('refid', text=self.obj['refid']))
        # These are default but not enforced values
        elt.append(self.pfsense.new_element('randomserial', text='disabled'))
        elt.append(self.pfsense.new_element('serial', text='0'))
        elt.append(self.pfsense.new_element('trust', text='disabled'))
        return elt

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
        self.root_elt.insert(self._find_last_ca_index(), self.target_elt)
        if self.crl is not None:
            crl_elt = self.pfsense.new_element('crl')
            self.crl['caref'] = self.obj['refid']
            if 'refid' not in self.crl:
                self.crl['refid'] = self.pfsense.uniqid()
            self.pfsense.copy_dict_to_element(self.crl, crl_elt)
            self.diff['after']['crl'] = self.crl['text']
            self.pfsense.root.append(crl_elt)
            self.refresh_crls = True

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        (before, changed) = super(PFSenseCAModule, self)._copy_and_update_target()

        if self.crl is not None:
            crl_elt = None

            # If a crlrefid is specified, update it or create a new one with that refid
            if self.params['crlrefid'] is not None:
                crl_elt = self._find_crl_by_refid(self.params['crlrefid'])
                self.crl['refid'] = self.params['crlrefid']
            else:
                if self.params['crlname'] is not None:
                    crl_elt = self._find_crl_by_name(self.params['crlname'])
                if crl_elt is None:
                    crl_elt = self._find_crl_for_ca(self.target_elt.find('refid').text)

            if crl_elt is None:
                changed = True
                crl_elt = self.pfsense.new_element('crl')
                self.crl['caref'] = self.target_elt.find('refid').text
                if 'refid' not in self.crl:
                    self.crl['refid'] = self.pfsense.uniqid()
                self.pfsense.copy_dict_to_element(self.crl, crl_elt)
                # Add after the existing ca entry
                self.pfsense.root.insert(self._find_this_ca_index() + 1, crl_elt)
                self.refresh_crls = True
            else:
                before['crl'] = crl_elt.find('text').text
                before['crlname'] = crl_elt.find('descr').text
                if 'crlname' not in self.crl:
                    self.crl['descr'] = before['crlname']
                before['crlrefid'] = crl_elt.find('refid').text
                if 'refid' not in self.crl:
                    self.crl['refid'] = before['crlrefid']
                if self.pfsense.copy_dict_to_element(self.crl, crl_elt):
                    changed = True
                    self.refresh_crls = True
            self.diff['after']['crl'] = self.crl['text']
            self.diff['after']['crlname'] = self.crl['descr']
            self.diff['after']['crlrefid'] = self.crl['refid']

        return (before, changed)

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return self.obj['descr']

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        return values

    ##############################
    # run
    #
    def _update(self):
        if self.params['state'] == 'present':
            # ca_import will base64 encode the cert + key  and will fix 'caref' for CAs that reference each other
            # $ca needs to be an existing reference (particularly 'refid' must be set) before calling ca_import
            # key and serial are optional arguments.  TODO - handle key and serial
            (dummy, stdout, stderr) = self.pfsense.phpshell("""
                init_config_arr(array('ca'));
                $ca =& lookup_ca('{refid}');
                ca_import($ca, '{cert}');
                print_r($ca);
                print_r($config['ca']);
                write_config('Update CA reference');
                ca_setup_trust_store();""".format(refid=self.target_elt.find('refid').text,
                                                  cert=base64.b64decode(self.target_elt.find('crt').text.encode()).decode()))

            crl_stdout = ''
            crl_stderr = ''
            if self.refresh_crls:
                if self.pfsense.is_at_least_2_5_0():
                    ipsec_configure = 'ipsec_configure'
                else:
                    ipsec_configure = 'vpn_ipsec_configure'
                (dummy, crl_stdout, crl_stderr) = self.pfsense.phpshell("""
                    require_once("openvpn.inc");
                    openvpn_refresh_crls();
                    require_once("vpn.inc");
                    {0}();""".format(ipsec_configure))
                return (dummy, stdout + crl_stdout, stderr + crl_stderr)

            return (dummy, stdout + crl_stdout, stderr + crl_stderr)
        else:
            return (None, '', '')

    def _pre_remove_target_elt(self):
        self.diff['after'] = {}
        if self.target_elt is not None:
            self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)
            crl_elt = self._find_crl_for_ca(self.target_elt.find('refid').text)
            self.cas.remove(self.target_elt)
            if crl_elt is not None:
                self.diff['before']['crl'] = crl_elt.find('text').text
                self.root_elt.remove(crl_elt)
        else:
            self.diff['before'] = {}


def main():
    module = AnsibleModule(
        argument_spec=PFSENSE_CA_ARGUMENT_SPEC,
        required_if=[
            ["state", "present", ["certificate"]],
        ],
        supports_check_mode=True)

    pfmodule = PFSenseCAModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
