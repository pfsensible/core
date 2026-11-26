# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.pfsensible.core.plugins.modules import pfsense_gateway_group
from ansible_collections.pfsensible.core.plugins.modules.pfsense_gateway_group import PFSenseGatewayGroupModule
from ansible_collections.pfsensible.core.plugins.module_utils.gateway import PFSenseGatewayModule
from .pfsense_module import TestPFSenseModule, set_module_args

# the members of GWGroup in the fixture
GWGROUP_MEMBERS = [
    dict(gateway="OPT3_VTIV4", tier=1, virtualip="address"),
    dict(gateway="GW_LAN", tier=2, virtualip="address"),
]


class TestPFSenseGatewayGroupModule(TestPFSenseModule):

    module = pfsense_gateway_group

    def __init__(self, *args, **kwargs):
        super(TestPFSenseGatewayGroupModule, self).__init__(*args, **kwargs)
        self.config_file = "pfsense_gateway_config.xml"
        self.pfmodule = PFSenseGatewayGroupModule

    def check_target_elt(self, obj, target_elt):
        """ test the xml definition """
        self.check_param_equal(obj, target_elt, "trigger", "down")
        self.check_param_equal_or_not_find(obj, target_elt, "descr")
        items = ["{0}|{1}|{2}".format(m["gateway"], m["tier"], m["virtualip"]) for m in obj["members"]]
        self.assertEqual([elt.text for elt in target_elt.findall("item")], items)

    def get_target_elt(self, obj, absent=False, module_result=None):
        """ get the generated xml definition """
        gateways_elt = self.assert_find_xml_elt(self.xml_result, "gateways")
        for item in gateways_elt.findall("gateway_group"):
            if item.findtext("name") == obj["name"]:
                return item
        return None

    def assert_applied(self):
        """ the change was applied with the same PHP as pfsense_gateway """
        self.phpshell.assert_called_once_with(PFSenseGatewayModule.get_update_cmds())

    ##############
    # tests
    #
    def test_gateway_group_create(self):
        """ test """
        members = [dict(gateway="GW_WAN", tier=1, virtualip="address"), dict(gateway="GW_LAN", tier=2, virtualip="address")]
        obj = dict(name="test_group", trigger="downloss", members=members)
        command = "create gateway_group 'test_group', trigger='downloss'"
        self.do_module_test(obj, command=command)
        self.assert_applied()

    def test_gateway_group_update(self):
        """ test """
        obj = dict(name="GWGroup", trigger="downloss", descr="Failover group", members=GWGROUP_MEMBERS)
        command = "update gateway_group 'GWGroup' set trigger='downloss'"
        self.do_module_test(obj, command=command)
        self.assert_applied()

    def test_gateway_group_update_noop(self):
        """ test: nothing to apply """
        obj = dict(name="GWGroup", trigger="down", descr="Failover group", members=GWGROUP_MEMBERS)
        self.do_module_test(obj, changed=False)
        self.phpshell.assert_not_called()

    def test_gateway_group_update_check_mode(self):
        """ test: nothing is applied in check mode """
        args = dict(name="GWGroup", trigger="downloss", descr="Failover group", members=GWGROUP_MEMBERS, _ansible_check_mode=True)
        with set_module_args(args):
            self.execute_module(changed=True)
        self.phpshell.assert_not_called()

    def test_gateway_group_delete(self):
        """ test """
        obj = dict(name="GWGroup")
        command = "delete gateway_group 'GWGroup'"
        self.do_module_test(obj, command=command, delete=True)
        self.assert_applied()
