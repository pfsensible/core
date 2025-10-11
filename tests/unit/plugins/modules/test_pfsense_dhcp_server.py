# Copyright: (c) 2024, David Rosado <davidrosza0@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.pfsensible.core.plugins.modules import pfsense_dhcp_server
from ansible_collections.pfsensible.core.plugins.modules.pfsense_dhcp_server import PFSenseDHCPServerModule
from .pfsense_module import TestPFSenseModule


class TestPFSenseDHCPServerModule(TestPFSenseModule):

    module = pfsense_dhcp_server

    def __init__(self, *args, **kwargs):
        super(TestPFSenseDHCPServerModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_dhcp_server_config.xml'
        self.pfmodule = PFSenseDHCPServerModule

    def check_target_elt(self, obj, target_elt, target_idx=-1):
        """ test the xml definition """
        # self.check_param_equal(obj, target_elt, 'interface')
        self.check_param_bool(obj, target_elt, 'enable')
        self.check_param_equal(obj, target_elt, 'range_from', xml_field='range/from')
        self.check_param_equal(obj, target_elt, 'range_to', xml_field='range/to')
        self.check_param_equal(obj, target_elt, 'failover_peerip')
        self.check_param_equal(obj, target_elt, 'defaultleasetime')
        self.check_param_equal(obj, target_elt, 'maxleasetime')
        self.check_param_equal(obj, target_elt, 'netmask')
        self.check_param_equal(obj, target_elt, 'gateway')
        self.check_param_equal(obj, target_elt, 'domain')
        self.check_param_equal(obj, target_elt, 'domainsearchlist')
        self.check_param_equal(obj, target_elt, 'ddnsdomain')
        self.check_param_equal(obj, target_elt, 'ddnsdomainprimary')
        self.check_param_equal(obj, target_elt, 'ddnsdomainkeyname')
        self.check_param_equal(obj, target_elt, 'ddnsdomainkeyalgorithm', default='hmac-md5')
        self.check_param_equal(obj, target_elt, 'ddnsdomainkey')
        self.check_param_equal(obj, target_elt, 'mac_allow')
        self.check_param_equal(obj, target_elt, 'mac_deny')
        self.check_param_equal(obj, target_elt, 'tftp')
        self.check_param_equal(obj, target_elt, 'ldap')
        self.check_param_equal(obj, target_elt, 'nextserver')
        self.check_param_equal(obj, target_elt, 'filename')
        self.check_param_equal(obj, target_elt, 'filename32')
        self.check_param_equal(obj, target_elt, 'filename64')
        self.check_param_equal(obj, target_elt, 'rootpath')
        self.check_param_equal(obj, target_elt, 'numberoptions')

    def get_target_elt(self, obj, absent=False, module_result=None):
        """ get the generated xml definition """
        root_elt = self.assert_find_xml_elt(self.xml_result, 'dhcpd')
        return root_elt.find(obj['interface'])

    ##############
    # tests
    #
    def test_dhcp_server_create(self):
        """ test creation of a new DHCP server """
        obj = dict(
            interface='opt2',
            enable=True,
            range_from='172.16.0.100',
            range_to='172.16.0.199',
            defaultleasetime=86400,
            maxleasetime=172800,
            domain='opt2.example.com'
        )
        command_as_list = ["create dhcp_server 'opt2', enable=True, range_from='172.16.0.100', ",
                           "range_to='172.16.0.199', failover_peerip='', defaultleasetime='86400', ",
                           "maxleasetime='172800', netmask='', gateway='', domain='opt2.example.com', ",
                           "domainsearchlist='', ddnsdomain='', ddnsdomainprimary='', ddnsdomainkeyname='', ",
                           "ddnsdomainkeyalgorithm='hmac-md5', ddnsdomainkey='', mac_allow='', mac_deny='', ",
                           "ddnsclientupdates='allow', tftp='', ldap='', nextserver='', filename='', filename32='', ",
                           "filename64='', rootpath='', numberoptions=''"]
        command = "".join(command_as_list)
        self.do_module_test(obj, command=command)

    def test_dhcp_server_update(self):
        """ test updating an existing DHCP server """
        obj = dict(
            interface='lan',
            enable=True,
            range_from='192.168.1.50',
            range_to='192.168.1.150',
            domain='updated.example.com'
        )
        command_as_list = ["update dhcp_server 'lan' set , range_from='192.168.1.50', range_to='192.168.1.150', ",
                           "defaultleasetime='', maxleasetime='', domain='updated.example.com'"]
        command = "".join(command_as_list)
        self.do_module_test(obj, command=command)

    def test_dhcp_server_update_disable_denyunknown(self):
        """ test disabling denyunknown from an existing DHCP server """
        obj = dict(
            interface='opt1',
            enable=True,
            range_from='10.0.0.100',
            range_to='10.0.0.199',
            denyunknown='disabled',
        )
        command_as_list = ["update dhcp_server 'opt1' set , ",
                           "defaultleasetime='', maxleasetime='', domain='', denyunknown=none"]
        command = "".join(command_as_list)
        self.do_module_test(obj, command=command)

    def test_dhcp_server_delete(self):
        """ test deletion of a DHCP server """
        obj = dict(interface='opt1', state='absent')
        command = "delete dhcp_server 'opt1'"
        self.do_module_test(obj, command=command, delete=True)

    def test_dhcp_server_create_invalid_interface(self):
        """ test creation with an invalid interface """
        obj = dict(interface='invalid_interface', enable=True, range_from='192.168.1.100', range_to='192.168.1.200')
        self.do_module_test(obj, failed=True, msg='The specified interface invalid_interface is not a valid logical interface or cannot be mapped to one')

    def test_dhcp_server_create_invalid_range(self):
        """ test creation with an invalid IP range """
        interface = 'lan'
        obj = dict(interface=interface, enable=True, range_from='192.168.1.200', range_to='192.168.1.100')
        self.do_module_test(obj, failed=True, msg=f'The interface {interface} must have a valid IP range pool')

    def test_dhcp_server_create_with_options(self):
        """ test creation with additional DHCP options """
        obj = dict(
            interface='opt2',
            enable=True,
            range_from='172.16.0.50',
            range_to='172.16.0.150',
            defaultleasetime=43200,
            maxleasetime=86400,
            domain='opt1.example.com',
            ddnsdomain='ddns.example.com',
            ddnsdomainprimary='172.16.0.60',
            tftp='172.16.0.63',
            disablepingcheck=True,
            winsserver=['172.16.0.80', '172.16.0.90']
        )
        command_as_list = ["create dhcp_server 'opt2', enable=True, range_from='172.16.0.50', ",
                           "range_to='172.16.0.150', failover_peerip='', defaultleasetime='43200', ",
                           "maxleasetime='86400', netmask='', gateway='', domain='opt1.example.com', ",
                           "domainsearchlist='', ddnsdomain='ddns.example.com', ddnsdomainprimary='172.16.0.60', ",
                           "ddnsdomainkeyname='', ddnsdomainkeyalgorithm='hmac-md5', ddnsdomainkey='', ",
                           "mac_allow='', mac_deny='', ddnsclientupdates='allow', tftp='172.16.0.63', ldap='', ",
                           "nextserver='', filename='', filename32='', filename64='', rootpath='', numberoptions=''"]
        command = "".join(command_as_list)
        self.do_module_test(obj, command=command)
