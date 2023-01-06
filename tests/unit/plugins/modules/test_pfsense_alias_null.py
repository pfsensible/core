# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import copy
import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_alias
from ansible_collections.pfsensible.core.plugins.module_utils.alias import PFSenseAliasModule

from .pfsense_module import TestPFSenseModule


# Test alias creation starting without an initial <aliases> element
class TestPFSenseAliasNullModule(TestPFSenseModule):

    module = pfsense_alias

    def __init__(self, *args, **kwargs):
        super(TestPFSenseAliasNullModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_alias_null_config.xml'
        self.pfmodule = PFSenseAliasModule

    ########################################################
    # Generic set of funcs used for testing aliases
    # First we run the module
    # Then, we check return values
    # Finally, we check the xml
    def do_alias_creation_test(self, alias, failed=False, msg='', command=None):
        """ test creation of a new alias """
        set_module_args(self.args_from_var(alias))
        result = self.execute_module(changed=True, failed=failed, msg=msg)

        if not failed:
            diff = dict(before='', after=alias)
            self.assertEqual(result['diff'], diff)
            self.assert_xml_elt_dict('aliases', dict(name=alias['name'], type=alias['type']), diff['after'])
            self.assertEqual(result['commands'], [command])
        else:
            self.assertFalse(self.load_xml_result())

    ##############
    # hosts
    #
    def test_host_create(self):
        """ test creation of a new host alias """
        alias = dict(name='adservers', address='10.0.0.1 10.0.0.2', descr='', type='host', detail='')
        command = "create alias 'adservers', type='host', address='10.0.0.1 10.0.0.2', descr='', detail=''"
        self.do_alias_creation_test(alias, command=command)
