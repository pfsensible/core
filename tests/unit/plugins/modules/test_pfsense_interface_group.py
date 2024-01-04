# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2024, Orioni Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.pfsensible.core.plugins.modules import pfsense_interface_group
from ansible_collections.pfsensible.core.plugins.module_utils.interface_group import PFSenseInterfaceGroupModule
from .pfsense_module import TestPFSenseModule


class TestPFSenseInterfaceGroupModule(TestPFSenseModule):

    module = pfsense_interface_group

    def __init__(self, *args, **kwargs):
        super(TestPFSenseInterfaceGroupModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_interface_config.xml'
        self.pfmodule = PFSenseInterfaceGroupModule

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

        super(TestPFSenseInterfaceGroupModule, self).setUp()

        self.php.return_value = None
        self.php.side_effect = php_mock

    def tearDown(self):
        """ mocking down """
        super(TestPFSenseInterfaceGroupModule, self).tearDown()

        self.php.stop()

    ##############
    # tests utils
    #
    def get_target_elt(self, obj, absent=False, module_result=None):
        """ get the generated interface group xml definition """
        elt_filter = {}
        elt_filter['ifname'] = obj['name']

        return self.assert_has_xml_tag('ifgroups', elt_filter, absent=absent)

    def check_target_elt(self, obj, target_elt):
        """ test the xml definition of interface group """

        # descr, members
        if obj.get('descr'):
            self.assert_xml_elt_equal(target_elt, 'descr', obj['descr'])
        else:
            self.assert_xml_elt_is_none_or_empty(target_elt, 'descr')

        if obj.get('members'):
            self.assert_xml_elt_equal(target_elt, 'members', ' '.join(obj['members']))
        else:
            self.assert_not_find_xml_elt(target_elt, 'members')

    ##############
    # tests
    #
    def test_interface_group_create(self):
        """ test creation of a new interface group """
        interface_group = dict(name='IFGROUP2', members=['wan', 'lan'])
        command = "create interface_group 'IFGROUP2', members='wan lan'"
        self.do_module_test(interface_group, command=command)

    def test_interface_group_create_with_descr(self):
        """ test creation of a new interface group with a description """
        interface_group = dict(name='IFGROUP2', members=['wan', 'lan'], descr='Primary interfaces')
        command = "create interface_group 'IFGROUP2', descr='Primary interfaces', members='wan lan'"
        self.do_module_test(interface_group, command=command)

    def test_interface_group_delete(self):
        """ test deletion of an interface group """
        interface_group = dict(name='IFGROUP1', state='absent')
        command = "delete interface_group 'IFGROUP1'"
        self.do_module_test(interface_group, delete=True, command=command)

    def test_interface_group_update_noop(self):
        """ test not updating a interface group """
        interface_group = dict(name='IFGROUP1', members=['opt1', 'opt3'])
        self.do_module_test(interface_group, changed=False)

    def test_interface_group_update_descr(self):
        """ test updating interface group description """
        interface_group = dict(name='IFGROUP1', members=['opt1', 'opt3'], descr='Opt Interfaces')
        command = "update interface_group 'IFGROUP1' set descr='Opt Interfaces'"
        self.do_module_test(interface_group, changed=True, command=command)

    def test_interface_group_update_members(self):
        """ test updating interface group members """
        interface_group = dict(name='IFGROUP1', members=['opt1', 'opt2'])
        command = "update interface_group 'IFGROUP1' set members='opt1 opt2'"
        self.do_module_test(interface_group, changed=True, command=command)

    def test_interface_group_error_no_members(self):
        """ test error no members specified """
        interface_group = dict(name='IFGROUP2', descr='Primary interfaces')
        msg = "state is present but all of the following are missing: members"
        self.do_module_test(interface_group, failed=True, msg=msg)

    def test_interface_group_error_member_does_not_exist(self):
        """ test error member does not exist """
        interface_group = dict(name='IFGROUP2', members=['blah'], descr='Primary interfaces')
        msg = 'Unknown interface name "blah".'
        self.do_module_test(interface_group, failed=True, msg=msg)

    def test_interface_group_error_members_not_uniq(self):
        """ test error member does not exist """
        interface_group = dict(name='IFGROUP2', members=['opt1', 'opt1'], descr='Primary interfaces')
        msg = 'List of members is not unique.'
        self.do_module_test(interface_group, failed=True, msg=msg)
