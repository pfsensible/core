# Copyright: (c) 2023 Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.pfsensible.core.plugins.modules import pfsense_dhcp_static
from ansible_collections.pfsensible.core.plugins.modules.pfsense_dhcp_static import PFSenseDHCPStaticModule
from .pfsense_module import TestPFSenseModule


class TestPFSenseDHCPStaticModule(TestPFSenseModule):

    module = pfsense_dhcp_static

    def __init__(self, *args, **kwargs):
        super(TestPFSenseDHCPStaticModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_dhcp_static_config.xml'
        self.pfmodule = PFSenseDHCPStaticModule

    def check_target_elt(self, obj, target_elt, target_idx=-1):
        """ test the xml definition """
        # checking destination address and ports
        self.check_param_equal(obj, target_elt, 'name', xml_field='cid')
        self.check_param_equal(obj, target_elt, 'macaddr', xml_field='mac')
        # Forced options
        for option in ['ipaddr', 'hostname', 'descr', 'filename',
                       'rootpath', 'defaultleasetime', 'maxleasetime',
                       'gateway', 'domain', 'domainsearchlist',
                       'ddnsdomain', 'ddnsdomainprimary', 'ddnsdomainsecondary',
                       'ddnsdomainkeyname', 'ddnsdomainkeyalgorithm', 'ddnsdomainkey',
                       'tftp', 'ldap', 'nextserver', 'filename32', 'filename64',
                       'filename32arm', 'filename64arm', 'uefihttpboot', 'numberoptions']:
            self.check_param_equal_or_present(obj, target_elt, option)
        # Non-forced options
        for option in ['winsserver', 'dnsserver', 'ntpserver']:
            self.check_param_equal(obj, target_elt, option)
        # Defaulted options
        self.check_param_equal(obj, target_elt, 'ddnsdomainkeyalgorithm', default='hmac-md5')

    def get_target_elt(self, obj, absent=False, module_result=None):
        """ get the generated xml definition """
        dhcpd_elt = self.assert_find_xml_elt(self.xml_result, 'dhcpd')
        root_elt = None
        for e in dhcpd_elt:
            if 'netif' not in obj or (module_result is not None and e.tag == module_result['netif']):
                if e.find('enable') is not None:
                    root_elt = e
                    break

        result = []
        if root_elt is not None:
            if 'name' in obj and 'macaddr' in obj:
                result = root_elt.findall("staticmap[cid='{0}'][mac='{1}']".format(obj['name'], obj['macaddr']))
            elif 'name' in obj:
                result = root_elt.findall("staticmap[cid='{0}']".format(obj['name']))
            else:
                result = root_elt.findall("staticmap[mac='{0}']".format(obj['macaddr']))

        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.fail('Found multiple static maps for cid {0}.'.format(obj['name']))
        else:
            return None

    ##############
    # tests
    #
    def test_dhcp_static_create(self):
        """ test """
        obj = dict(name='test_entry', macaddr='ab:ab:ab:ab:ab:ac', ipaddr='10.0.0.101', netif='opt1')
        command = (
            "create dhcp_static 'test_entry', macaddr='ab:ab:ab:ab:ab:ac', ipaddr='10.0.0.101'"
        )
        self.do_module_test(obj, command=command)

    def test_dhcp_static_create_empty(self):
        """ test """
        obj = dict(name='test_entry', macaddr='ab:ab:ab:ab:ab:ac', ipaddr='10.10.0.101', netif='opt2')
        command = (
            "create dhcp_static 'test_entry', macaddr='ab:ab:ab:ab:ab:ac', ipaddr='10.10.0.101'"
        )
        self.do_module_test(obj, command=command)

    def test_dhcp_static_create_display(self):
        """ test create with netif display name """
        obj = dict(name='test_entry', macaddr='ab:ab:ab:ab:ab:ac', ipaddr='10.0.0.101', netif='pub')
        command = (
            "create dhcp_static 'test_entry', macaddr='ab:ab:ab:ab:ab:ac', ipaddr='10.0.0.101'"
        )
        self.do_module_test(obj, command=command)

    def test_dhcp_static_create_arp_table_static_entry(self):
        """ test create with arp_table_static_entry """
        obj = dict(name='test_entry', macaddr='ab:ab:ab:ab:ab:ab', ipaddr='10.0.0.101', netif='opt1', arp_table_static_entry=True)
        command = (
            "create dhcp_static 'test_entry', macaddr='ab:ab:ab:ab:ab:ab', ipaddr='10.0.0.101', arp_table_static_entry=True"
        )
        self.do_module_test(obj, command=command)

    def test_dhcp_static_create_wrong_subnet(self):
        """ test create with IP address in the wrong subnet """
        obj = dict(name='test_entry', macaddr='ab:ab:ab:ab:ab:ab', ipaddr='1.2.3.4', netif='opt1')
        self.do_module_test(obj, failed=True, msg='The IP address must lie in the opt1 subnet.')

    def test_dhcp_static_create_no_netif(self):
        """ test create with no netif """
        obj = dict(name='test_entry', macaddr='ab:ab:ab:ab:ab:ab', ipaddr='1.2.3.4')
        self.do_module_test(obj, failed=True, msg='Multiple DHCP servers enabled and no netif specified')

    def test_dhcp_static_create_ifgroup(self):
        """ test create with interface group """
        obj = dict(name='test_entry', macaddr='ab:ab:ab:ab:ab:ab', ipaddr='1.2.3.4', netif='IFGROUP1')
        self.do_module_test(obj, failed=True, msg='DHCP cannot be configured for interface groups')

    def test_dhcp_static_create_invalid_macaddr(self):
        """ test create with invalid macaddr """
        msg = 'A valid MAC address must be specified.'
        obj = dict(name='test_entry', macaddr='ab:ab:ab:ab:ab:ab:ab', ipaddr='10.10.0.101', netif='opt2')
        self.do_module_test(obj, failed=True, msg=msg)
        obj = dict(name='test_entry', macaddr='ab:ab:ab:ab:ab:hh', ipaddr='10.10.0.101', netif='opt2')
        self.do_module_test(obj, failed=True, msg=msg)

    def test_dhcp_static_delete_macaddr(self):
        """ test """
        obj = dict(macaddr='ab:ab:ab:ab:ab:ab', netif='opt1', state='absent')
        command = "delete dhcp_static ''"

    def test_dhcp_static_delete_name(self):
        """ test """
        obj = dict(name='dhcphostid', netif='opt1', state='absent')
        command = "delete dhcp_static 'dhcphostid'"
        self.do_module_test(obj, command=command, delete=True)
