# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.pfsensible.core.plugins.modules import pfsense_interface
from ansible_collections.pfsensible.core.plugins.module_utils.interface import PFSenseInterfaceModule
from .pfsense_module import TestPFSenseModule


class TestPFSenseInterfaceModule(TestPFSenseModule):

    module = pfsense_interface

    def __init__(self, *args, **kwargs):
        super(TestPFSenseInterfaceModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_interface_config.xml'
        self.pfmodule = PFSenseInterfaceModule

    def setUp(self):
        """ mocking up """

        def php_mock(command):
            if 'get_interface_list' in command:
                interfaces = dict()
                interfaces['vmx0'] = dict()
                interfaces['vmx1'] = dict(descr='notuniq')
                interfaces['vmx2'] = dict(descr='notuniq')
                interfaces['vmx3'] = dict()
                interfaces['vmx0.100'] = dict(descr='uniq')
                interfaces['vmx1.1100'] = dict()
                return interfaces
            return ['autoselect']

        super(TestPFSenseInterfaceModule, self).setUp()

        self.php.return_value = None
        self.php.side_effect = php_mock

    def tearDown(self):
        """ mocking down """
        super(TestPFSenseInterfaceModule, self).tearDown()

        self.php.stop()

    ##############
    # tests utils
    #
    def get_target_elt(self, obj, absent=False, module_result=None):
        """ get the generated interface xml definition """
        elt_filter = {}
        elt_filter['descr'] = obj['descr']

        return self.assert_has_xml_tag('interfaces', elt_filter, absent=absent)

    def check_target_elt(self, obj, target_elt):
        """ test the xml definition of interface """
        if 'interface_descr' in obj and obj['interface_descr'] == 'uniq':
            obj['interface'] = 'vmx0.100'
        self.assert_xml_elt_equal(target_elt, 'if', self.unalias_interface(obj['interface'], physical=True))

        # bools
        if obj.get('enable'):
            self.assert_xml_elt_is_none_or_empty(target_elt, 'enable')
        else:
            self.assert_not_find_xml_elt(target_elt, 'enable')

        if obj.get('blockpriv'):
            self.assert_xml_elt_equal(target_elt, 'blockpriv', '')
        else:
            self.assert_not_find_xml_elt(target_elt, 'blockpriv')

        if obj.get('blockbogons'):
            self.assert_xml_elt_equal(target_elt, 'blockbogons', '')
        else:
            self.assert_not_find_xml_elt(target_elt, 'blockbogons')

        # ipv4 type related
        if obj.get('ipv4_type') is None or obj.get('ipv4_type') == 'none':
            self.assert_not_find_xml_elt(target_elt, 'ipaddr')
            self.assert_not_find_xml_elt(target_elt, 'subnet')
            self.assert_not_find_xml_elt(target_elt, 'gateway')
        elif obj.get('ipv4_type') == 'static':
            if obj.get('ipv4_address'):
                self.assert_xml_elt_equal(target_elt, 'ipaddr', obj['ipv4_address'])
            if obj.get('ipv4_prefixlen'):
                self.assert_xml_elt_equal(target_elt, 'subnet', str(obj['ipv4_prefixlen']))
            if obj.get('ipv4_gateway'):
                self.assert_xml_elt_equal(target_elt, 'gateway', obj['ipv4_gateway'])

        # ipv6 type related
        if obj.get('ipv6_type') is None or obj.get('ipv6_type') in ['none', 'slaac']:
            self.assert_not_find_xml_elt(target_elt, 'ipaddrv6')
            self.assert_not_find_xml_elt(target_elt, 'subnetv6')
            self.assert_not_find_xml_elt(target_elt, 'gatewayv6')
        elif obj.get('ipv6_type') == 'static':
            if obj.get('ipv6_address'):
                self.assert_xml_elt_equal(target_elt, 'ipaddrv6', obj['ipv6_address'])
            if obj.get('ipv6_prefixlen'):
                self.assert_xml_elt_equal(target_elt, 'subnetv6', str(obj['ipv6_prefixlen']))
            if obj.get('ipv6_gateway'):
                self.assert_xml_elt_equal(target_elt, 'gatewayv6', obj['ipv6_gateway'])

        # mac, mss, mtu
        if obj.get('mac'):
            self.assert_xml_elt_equal(target_elt, 'spoofmac', obj['mac'])
        else:
            self.assert_xml_elt_is_none_or_empty(target_elt, 'spoofmac')

        if obj.get('mtu'):
            self.assert_xml_elt_equal(target_elt, 'mtu', str(obj['mtu']))
        else:
            self.assert_not_find_xml_elt(target_elt, 'mtu')

        if obj.get('mss'):
            self.assert_xml_elt_equal(target_elt, 'mss', str(obj['mss']))
        else:
            self.assert_not_find_xml_elt(target_elt, 'mss')

    ##############
    # tests
    #
    def test_interface_create_no_address(self):
        """ test creation of a new interface with no address """
        interface = dict(descr='VOICE', interface='vmx0.100')
        command = "create interface 'VOICE', port='vmx0.100'"
        self.do_module_test(interface, command=command)

    def test_interface_create_by_descr(self):
        """ test creation of a new interface with interface_descr """
        interface = dict(descr='VOICE', interface_descr='uniq')
        command = "create interface 'VOICE', port='vmx0.100'"
        self.do_module_test(interface, command=command)

    def test_interface_create_static(self):
        """ test creation of a new interface with a static ip """
        interface = dict(descr='VOICE', interface='vmx0.100', ipv4_type='static', ipv4_address='10.20.30.40', ipv4_prefixlen=24)
        command = "create interface 'VOICE', port='vmx0.100', ipv4_type='static', ipv4_address='10.20.30.40', ipv4_prefixlen='24'"
        self.do_module_test(interface, command=command)

    def test_interface_create_static_ipv6(self):
        """ test creation of a new interface with a static ipv6 """
        interface = dict(descr='VOICE', interface='vmx0.100', ipv6_type='static', ipv6_address='3001::2001:22', ipv6_prefixlen=56)
        command = "create interface 'VOICE', port='vmx0.100', ipv6_type='static', ipv6_address='3001::2001:22', ipv6_prefixlen='56'"
        self.do_module_test(interface, command=command)

    def test_interface_create_slaac(self):
        """ test creation of a new interface with slaac """
        interface = dict(descr='VOICE', interface='vmx0.100', ipv6_type='slaac')
        command = "create interface 'VOICE', port='vmx0.100', ipv6_type='slaac'"
        self.do_module_test(interface, command=command)

    def test_interface_create_none_mac_mtu_mss(self):
        """ test creation of a new interface """
        interface = dict(descr='VOICE', interface='vmx0.100', mac='00:11:22:33:44:55', mtu=1500, mss=1100)
        command = "create interface 'VOICE', port='vmx0.100', mac='00:11:22:33:44:55', mtu='1500', mss='1100'"
        self.do_module_test(interface, command=command)

    def test_interface_delete(self):
        """ test deletion of an interface """
        interface = dict(descr='vt1')
        command = "delete interface 'vt1'"
        self.do_module_test(interface, delete=True, command=command)

    def test_interface_delete_lan(self):
        """ test deletion of an interface """
        interface = dict(descr='lan')
        commands = [
            "delete rule_separator 'test_separator', interface='lan'",
            "update rule 'floating_rule_2' on 'floating(lan,wan,lan_1100)' set interface='wan,lan_1100'",
            "delete rule 'floating_rule_1' on 'floating(lan)'",
            "delete rule 'antilock_out_1' on 'lan'",
            "delete rule 'antilock_out_2' on 'lan'",
            "delete rule 'antilock_out_3' on 'lan'",
            "delete interface 'lan'"
        ]
        self.do_module_test(interface, delete=True, command=commands)

    def test_interface_delete_fails(self):
        """ test deletion of an interface that is part of a group """
        interface = dict(descr='lan_1100')
        msg = "The interface is part of the group IFGROUP1. Please remove it from the group first."
        self.do_module_test(interface, delete=True, failed=True, msg=msg)

    def test_interface_update_noop(self):
        """ test not updating a interface """
        interface = dict(descr='lan_1100', interface='vmx1.1100', enable=True, ipv4_type='static', ipv4_address='172.16.151.210', ipv4_prefixlen=24)
        self.do_module_test(interface, changed=False)

    def test_interface_update_name(self):
        """ test updating interface name """
        interface = dict(descr='wlan_1100', interface='vmx1.1100', enable=True, ipv4_type='static', ipv4_address='172.16.151.210', ipv4_prefixlen=24)
        command = "update interface 'lan_1100' set interface='wlan_1100'"
        self.do_module_test(interface, changed=True, command=command)

    def test_interface_update_enable(self):
        """ test disabling interface """
        interface = dict(descr='lan_1100', interface='vmx1.1100', enable=False, ipv4_type='static', ipv4_address='172.16.151.210', ipv4_prefixlen=24)
        command = "update interface 'lan_1100' set enable=False"
        self.do_module_test(interface, changed=True, command=command)

    def test_interface_update_enable2(self):
        """ test enabling interface """
        interface = dict(descr='vt1', interface='vmx3', enable=True)
        command = "update interface 'vt1' set enable=True"
        self.do_module_test(interface, changed=True, command=command)

    def test_interface_update_mac(self):
        """ test updating mac """
        interface = dict(descr='lan_1100', interface='vmx1.1100', enable=True, ipv4_type='static',
                         ipv4_address='172.16.151.210', ipv4_prefixlen=24, mac='00:11:22:33:44:55', )
        command = "update interface 'lan_1100' set mac='00:11:22:33:44:55'"
        self.do_module_test(interface, changed=True, command=command)

    def test_interface_update_blocks(self):
        """ test updating block fields """
        interface = dict(descr='lan_1100', interface='vmx1.1100', enable=True, ipv4_type='static',
                         ipv4_address='172.16.151.210', ipv4_prefixlen=24, blockpriv=True, blockbogons=True)
        command = "update interface 'lan_1100' set blockpriv=True, blockbogons=True"
        self.do_module_test(interface, changed=True, command=command)

    def test_interface_error_used(self):
        """ test error already used """
        interface = dict(descr='lan_1100', interface='vmx1', enable=True, ipv4_type='static', ipv4_address='172.16.151.210', ipv4_prefixlen=24)
        msg = "Port vmx1 is already in use on interface lan"
        self.do_module_test(interface, failed=True, msg=msg)

    def test_interface_error_gw(self):
        """ test error no such gateway """
        interface = dict(descr='lan_1100', interface='vmx1.1100', enable=True, ipv4_type='static',
                         ipv4_address='172.16.151.210', ipv4_prefixlen=24, ipv4_gateway='voice_gw')
        msg = "Gateway voice_gw does not exist on lan_1100"
        self.do_module_test(interface, failed=True, msg=msg)

    def test_interface_error_if(self):
        """ test error no such interface """
        interface = dict(descr='wlan_1100', interface='vmx1.1200', enable=True, ipv4_type='static',
                         ipv4_address='172.16.151.210', ipv4_prefixlen=24, ipv4_gateway='voice_gw')
        msg = "vmx1.1200 can't be assigned. Interface may only be one the following: ['vmx0', 'vmx1', 'vmx2', 'vmx3', 'vmx0.100', 'vmx1.1100']"
        self.do_module_test(interface, failed=True, msg=msg)

    def test_interface_error_eq(self):
        """ test error same ipv4 address """
        interface = dict(descr='VOICE', interface='vmx0.100', ipv4_type='static', ipv4_address='192.168.1.242', ipv4_prefixlen=32)
        msg = "IP address 192.168.1.242/32 is being used by or overlaps with: lan (192.168.1.242/24)"
        self.do_module_test(interface, failed=True, msg=msg)

    def test_interface_error_overlaps1(self):
        """ test error same ipv4 address """
        interface = dict(descr='VOICE', interface='vmx0.100', ipv4_type='static', ipv4_address='192.168.1.1', ipv4_prefixlen=30)
        msg = "IP address 192.168.1.1/30 is being used by or overlaps with: lan (192.168.1.242/24)"
        self.do_module_test(interface, failed=True, msg=msg)

    def test_interface_error_overlaps2(self):
        """ test error same ipv4 address """
        interface = dict(descr='VOICE', interface='vmx0.100', ipv4_type='static', ipv4_address='192.168.1.1', ipv4_prefixlen=22)
        msg = "IP address 192.168.1.1/22 is being used by or overlaps with: lan (192.168.1.242/24)"
        self.do_module_test(interface, failed=True, msg=msg)

    def test_interface_error_inet6_eq(self):
        """ test error same ipv6 address """
        interface = dict(descr='VOICE', interface='vmx0.100', ipv6_type='static', ipv6_address='2001::2001:22', ipv6_prefixlen=127)
        msg = "IP address 2001::2001:22/127 is being used by or overlaps with: lan (2001::2001:22/64)"
        self.do_module_test(interface, failed=True, msg=msg)

    def test_interface_error_inet6_overlaps1(self):
        """ test error same ipv6 address """
        interface = dict(descr='VOICE', interface='vmx0.100', ipv6_type='static', ipv6_address='2001::2001:1', ipv6_prefixlen=64)
        msg = "IP address 2001::2001:1/64 is being used by or overlaps with: lan (2001::2001:22/64)"
        self.do_module_test(interface, failed=True, msg=msg)

    def test_interface_error_inet6_overlaps2(self):
        """ test error same ipv6 address """
        interface = dict(descr='VOICE', interface='vmx0.100', ipv6_type='static', ipv6_address='2001::2001', ipv6_prefixlen=56)
        msg = "IP address 2001::2001/56 is being used by or overlaps with: lan (2001::2001:22/64)"
        self.do_module_test(interface, failed=True, msg=msg)

    def test_interface_delete_sub(self):
        """ test delete sub interface """
        interface = dict(descr='lan_1200', interface='vmx1.1200')
        command = "delete interface 'lan_1200'"
        self.do_module_test(interface, delete=True, command=command)

    def test_interface_error_not_uniq(self):
        """ test creation of a new interface with interface_descr """
        interface = dict(descr='VOICE', interface_descr='notuniq')
        msg = 'Multiple interfaces found for "notuniq"'
        self.do_module_test(interface, failed=True, msg=msg)
