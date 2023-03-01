# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.pfsensible.core.plugins.modules import pfsense_ipsec
from ansible_collections.pfsensible.core.plugins.module_utils.ipsec import PFSenseIpsecModule
from .pfsense_module import TestPFSenseModule
from parameterized import parameterized


class TestPFSenseIpsecModule(TestPFSenseModule):

    module = pfsense_ipsec

    def __init__(self, *args, **kwargs):
        super(TestPFSenseIpsecModule, self).__init__(*args, **kwargs)
        self.pfmodule = PFSenseIpsecModule

    def get_config_file(self):
        """ get config file """
        if self.get_version.return_value.startswith("2.4."):
            return '2.4/pfsense_ipsec_config.xml'

        return 'pfsense_ipsec_config.xml'

    ##############
    # tests utils
    #
    def get_target_elt(self, obj, absent=False):
        """ get the generated ipsec xml definition """
        elt_filter = {}
        elt_filter['descr'] = obj['descr']

        return self.assert_has_xml_tag('ipsec', elt_filter, absent=absent)

    @staticmethod
    def caref(descr):
        """ return refid for ca """
        if descr == 'test ca':
            return '5db509cfed87d'
        if descr == 'test ca copy':
            return '5db509cfed87e'
        return ''

    @staticmethod
    def certref(descr):
        """ return refid for cert """
        if descr == 'webConfigurator default (5c00e5f9029df)':
            return '5c00e5f9029df'
        if descr == 'webConfigurator default copy':
            return '5c00e5f9029de'
        return ''

    def check_target_elt(self, obj, target_elt):
        """ test the xml definition of ipsec elt """

        # bools
        if obj.get('disabled'):
            self.assert_xml_elt_is_none_or_empty(target_elt, 'disabled')
        else:
            self.assert_not_find_xml_elt(target_elt, 'disabled')

        if self.get_version.return_value == "2.4.4":
            if obj.get('disable_rekey'):
                self.assert_xml_elt_is_none_or_empty(target_elt, 'disable_rekey')
                self.assert_not_find_xml_elt(target_elt, 'margintime')
            else:
                self.assert_not_find_xml_elt(target_elt, 'disable_rekey')
                if obj.get('margintime'):
                    self.assert_xml_elt_equal(target_elt, 'margintime', obj['margintime'])
                else:
                    self.assert_xml_elt_is_none_or_empty(target_elt, 'margintime')
        else:
            self.check_param_bool(obj, target_elt, 'gw_duplicates')
            self.check_param_equal_or_not_find(obj, target_elt, 'nattport')
            self.check_param_equal(obj, target_elt, 'rekey_time')
            self.check_param_equal(obj, target_elt, 'reauth_time')
            self.check_param_equal(obj, target_elt, 'rand_time')

        # Added in 2.5.2
        if obj.get('startaction'):
            self.assert_xml_elt_equal(target_elt, 'startaction', obj['startaction'])
        if obj.get('closeaction'):
            self.assert_xml_elt_equal(target_elt, 'closeaction', obj['closeaction'])

        if obj.get('disable_reauth'):
            self.assert_xml_elt_is_none_or_empty(target_elt, 'reauth_enable')
        else:
            self.assert_not_find_xml_elt(target_elt, 'reauth_enable')

        if obj.get('splitconn'):
            self.assert_xml_elt_is_none_or_empty(target_elt, 'splitconn')
        else:
            self.assert_not_find_xml_elt(target_elt, 'splitconn')

        if obj.get('enable_dpd') is None or obj.get('enable_dpd'):
            if obj.get('dpd_delay') is not None:
                self.assert_xml_elt_equal(target_elt, 'dpd_delay', obj['dpd_delay'])
            else:
                self.assert_xml_elt_equal(target_elt, 'dpd_delay', '10')

            if obj.get('dpd_maxfail') is not None:
                self.assert_xml_elt_equal(target_elt, 'dpd_maxfail', obj['dpd_maxfail'])
            else:
                self.assert_xml_elt_equal(target_elt, 'dpd_maxfail', '5')
        else:
            self.assert_not_find_xml_elt(target_elt, 'dpd_delay')
            self.assert_not_find_xml_elt(target_elt, 'dpd_maxfail')

        if obj.get('mobike'):
            self.assert_xml_elt_equal(target_elt, 'mobike', obj['mobike'])

        # iketype & mode
        self.assert_xml_elt_equal(target_elt, 'iketype', obj['iketype'])
        if obj.get('mode') is not None:
            self.assert_xml_elt_equal(target_elt, 'mode', obj['mode'])

        if obj.get('nat_traversal') is not None:
            self.assert_xml_elt_equal(target_elt, 'nat_traversal', obj['nat_traversal'])
        else:
            self.assert_xml_elt_equal(target_elt, 'nat_traversal', 'on')

        # auth
        self.assert_xml_elt_equal(target_elt, 'authentication_method', obj['authentication_method'])
        if obj['authentication_method'] == 'rsasig':
            self.assert_xml_elt_equal(target_elt, 'certref', self.certref(obj['certificate']))
            self.assert_xml_elt_equal(target_elt, 'caref', self.caref(obj['certificate_authority']))
            self.assert_xml_elt_is_none_or_empty(target_elt, 'pre-shared-key')
        else:
            self.assert_xml_elt_is_none_or_empty(target_elt, 'certref')
            self.assert_xml_elt_is_none_or_empty(target_elt, 'caref')
            self.assert_xml_elt_equal(target_elt, 'pre-shared-key', obj['preshared_key'])

        # ids
        if obj.get('myid_type') is not None:
            self.assert_xml_elt_equal(target_elt, 'myid_type', obj['myid_type'])
        else:
            self.assert_xml_elt_equal(target_elt, 'myid_type', 'myaddress')
        if obj.get('myid_data') is not None:
            self.assert_xml_elt_equal(target_elt, 'myid_data', obj['myid_data'])

        if obj.get('peerid_type') is not None:
            self.assert_xml_elt_equal(target_elt, 'peerid_type', obj['peerid_type'])
        else:
            self.assert_xml_elt_equal(target_elt, 'peerid_type', 'peeraddress')
        if obj.get('peerid_data') is not None:
            self.assert_xml_elt_equal(target_elt, 'peerid_data', obj['peerid_data'])

        # misc
        self.assert_xml_elt_equal(target_elt, 'interface', self.unalias_interface(obj['interface']))

        if obj.get('protocol') is not None:
            self.assert_xml_elt_equal(target_elt, 'protocol', obj['protocol'])
        else:
            self.assert_xml_elt_equal(target_elt, 'protocol', 'inet')
        self.assert_xml_elt_equal(target_elt, 'remote-gateway', obj['remote_gateway'])

        if obj.get('lifetime') is not None:
            self.assert_xml_elt_equal(target_elt, 'lifetime', obj['lifetime'])
        else:
            self.assert_xml_elt_equal(target_elt, 'lifetime', '28800')

    def strip_commands(self, commands):
        if self.get_version.return_value.startswith("2.4."):
            commands = commands.replace("nattport='4501', ", "")
            commands = commands.replace("rekey_time='', ", "")
            commands = commands.replace("reauth_time='', ", "")
            commands = commands.replace("rand_time='', ", "")
        else:
            commands = commands.replace("margintime='', ", "")
            commands = commands.replace("disable_rekey=False, ", "")

        return commands

    def strip_params(self, params):
        if self.get_version.return_value.startswith("2.4."):
            params.pop('nattport', None)
            params.pop('gw_duplicates', None)
        return params

    ##############
    # tests
    #
    def test_ipsec_create_ikev2(self):
        """ test creation of a new ipsec tunnel with 2.5.2 params """
        ipsec = dict(
            descr='new_tunnel', interface='lan_100', remote_gateway='1.2.3.4', nattport=4501, iketype='ikev2',
            authentication_method='pre_shared_key', preshared_key='1234', gw_duplicates=True, rekey_time=2500, reauth_time=2600, rand_time=2700)
        command = (
            "create ipsec 'new_tunnel', iketype='ikev2', protocol='inet', interface='lan_100', remote_gateway='1.2.3.4', nattport='4501', "
            "authentication_method='pre_shared_key', preshared_key='1234', myid_type='myaddress', peerid_type='peeraddress', lifetime='28800', "
            "rekey_time='2500', reauth_time='2600', rand_time='2700', "
            "mobike='off', gw_duplicates=True, startaction='', closeaction='', nat_traversal='on', enable_dpd=True, dpd_delay='10', dpd_maxfail='5'")
        self.do_module_test(ipsec, command=command)

    def test_ipsec_create_ikev1(self):
        """ test creation of a new ipsec tunnel """
        ipsec = dict(
            descr='new_tunnel', interface='lan_100', remote_gateway='1.2.3.4', iketype='ikev1',
            authentication_method='pre_shared_key', preshared_key='1234', mode='main', startaction='none', closeaction='none')
        command = (
            "create ipsec 'new_tunnel', iketype='ikev1', mode='main', protocol='inet', interface='lan_100', remote_gateway='1.2.3.4', "
            "authentication_method='pre_shared_key', preshared_key='1234', myid_type='myaddress', peerid_type='peeraddress', lifetime='28800', "
            "rekey_time='', reauth_time='', rand_time='', "
            "disable_rekey=False, margintime='', startaction='none', closeaction='none', nat_traversal='on', enable_dpd=True, dpd_delay='10', dpd_maxfail='5'")
        self.do_module_test(ipsec, command=command)

    def test_ipsec_create_vip_descr(self):
        """ test creation of a new ipsec tunnel with vip: interface name """
        ipsec = dict(
            descr='new_tunnel', interface='vip:WAN CARP', remote_gateway='1.2.3.4', iketype='ikev1',
            authentication_method='pre_shared_key', preshared_key='1234', mode='main', startaction='start', closeaction='start')
        command = (
            "create ipsec 'new_tunnel', iketype='ikev1', mode='main', protocol='inet', interface='vip:WAN CARP', remote_gateway='1.2.3.4', "
            "authentication_method='pre_shared_key', preshared_key='1234', myid_type='myaddress', peerid_type='peeraddress', lifetime='28800', "
            "rekey_time='', reauth_time='', rand_time='', disable_rekey=False, margintime='', startaction='start', closeaction='start', "
            "nat_traversal='on', enable_dpd=True, dpd_delay='10', dpd_maxfail='5'")
        self.do_module_test(ipsec, command=command)

    def test_ipsec_create_vip_subnet(self):
        """ test creation of a new ipsec tunnel with vip: interface address """
        ipsec = dict(
            descr='new_tunnel', interface='vip:151.25.19.11', remote_gateway='1.2.3.4', iketype='ikev1',
            authentication_method='pre_shared_key', preshared_key='1234', mode='main', startaction='trap', closeaction='trap')
        command = (
            "create ipsec 'new_tunnel', iketype='ikev1', mode='main', protocol='inet', interface='vip:151.25.19.11', remote_gateway='1.2.3.4', "
            "authentication_method='pre_shared_key', preshared_key='1234', myid_type='myaddress', peerid_type='peeraddress', lifetime='28800', "
            "rekey_time='', reauth_time='', rand_time='', "
            "disable_rekey=False, margintime='', startaction='trap', closeaction='trap', nat_traversal='on', enable_dpd=True, dpd_delay='10', dpd_maxfail='5'")
        self.do_module_test(ipsec, command=command)

    def test_ipsec_create_auto(self):
        """ test creation of a new ipsec tunnel """
        ipsec = dict(
            descr='new_tunnel', interface='lan_100', remote_gateway='1.2.3.4', iketype='auto',
            authentication_method='pre_shared_key', preshared_key='1234', mode='main')
        command = (
            "create ipsec 'new_tunnel', iketype='auto', mode='main', protocol='inet', interface='lan_100', remote_gateway='1.2.3.4', "
            "authentication_method='pre_shared_key', preshared_key='1234', myid_type='myaddress', peerid_type='peeraddress', lifetime='28800', "
            "rekey_time='', reauth_time='', rand_time='', "
            "disable_rekey=False, margintime='', startaction='', closeaction='', nat_traversal='on', enable_dpd=True, dpd_delay='10', dpd_maxfail='5'")
        self.do_module_test(ipsec, command=command)

    def test_ipsec_delete(self):
        """ test deletion of an ipsec """
        ipsec = dict(descr='test_tunnel', state='absent')
        command = "delete ipsec 'test_tunnel'"
        self.do_module_test(ipsec, delete=True, command=command)

    def test_ipsec_update_noop(self):
        """ test not updating a ipsec """
        ipsec = dict(
            descr='test_tunnel', interface='lan_100', remote_gateway='1.2.4.8', iketype='ikev2',
            authentication_method='pre_shared_key', preshared_key='1234')
        self.do_module_test(ipsec, changed=False)

    def test_ipsec_update_2_5_0(self):
        """ test updating 2_5_0 fields ipsec """
        ipsec = dict(
            descr='test_tunnel', interface='lan_100', remote_gateway='1.2.4.8', iketype='ikev2',
            nattport=4501, gw_duplicates=True, rekey_time=2500, reauth_time=2600, rand_time=2700,
            authentication_method='pre_shared_key', preshared_key='1234')
        command = "update ipsec 'test_tunnel' set nattport='4501', rekey_time='2500', reauth_time='2600', rand_time='2700', gw_duplicates=True"
        self.do_module_test(ipsec, command=command)

    def test_ipsec_update_remove_2_5_0(self):
        """ test updating 2_5_0 fields ipsec """
        ipsec = dict(
            descr='test_tunnel_2_5_0', interface='lan_100', remote_gateway='1.2.4.16', iketype='ikev2',
            authentication_method='pre_shared_key', preshared_key='1234')
        command = "update ipsec 'test_tunnel_2_5_0' set nattport=none, rekey_time='', reauth_time='', rand_time='', gw_duplicates=False"
        self.do_module_test(ipsec, command=command)

    def test_ipsec_update_ike(self):
        """ test updating ike """
        ipsec = dict(
            descr='test_tunnel', interface='lan_100', remote_gateway='1.2.4.8', iketype='ikev1',
            authentication_method='pre_shared_key', preshared_key='1234', mode='main')
        command = "update ipsec 'test_tunnel' set iketype='ikev1', mode='main'"
        self.do_module_test(ipsec, command=command)

    def test_ipsec_update_gw(self):
        """ test updating gw """
        ipsec = dict(
            descr='test_tunnel', interface='lan_100', remote_gateway='1.2.3.5', iketype='ikev2',
            authentication_method='pre_shared_key', preshared_key='1234')
        command = "update ipsec 'test_tunnel' set remote_gateway='1.2.3.5'"
        self.do_module_test(ipsec, command=command)

    def test_ipsec_update_auth(self):
        """ test updating auth """
        ipsec = dict(
            descr='test_tunnel', interface='lan_100', remote_gateway='1.2.4.8', iketype='ikev2',
            authentication_method='rsasig', certificate='webConfigurator default (5c00e5f9029df)', certificate_authority='test ca')
        command = (
            "update ipsec 'test_tunnel' set authentication_method='rsasig', "
            "certificate='webConfigurator default (5c00e5f9029df)', certificate_authority='test ca'")
        self.do_module_test(ipsec, command=command)

    def test_ipsec_update_cert(self):
        """ test updating certificates """
        ipsec = dict(
            descr='test_tunnel2', interface='lan_100', remote_gateway='1.2.3.6', iketype='ikev2',
            authentication_method='rsasig', certificate='webConfigurator default copy', certificate_authority='test ca copy')
        command = "update ipsec 'test_tunnel2' set certificate='webConfigurator default copy', certificate_authority='test ca copy'"
        self.do_module_test(ipsec, command=command)

    def test_ipsec_duplicate_gw(self):
        """ test using a duplicate gw """
        ipsec = dict(
            descr='new_tunnel', interface='lan_100', remote_gateway='1.2.4.8', iketype='ikev1',
            authentication_method='pre_shared_key', preshared_key='1234', mode='main')
        msg = 'The remote gateway "1.2.4.8" is already used by phase1 "test_tunnel".'
        self.do_module_test(ipsec, msg=msg, failed=True)
