# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys
import xml.etree.ElementTree as ET

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_nat_port_forward
from ansible_collections.pfsensible.core.plugins.module_utils.nat_port_forward import PFSenseNatPortForwardModule
from .pfsense_module import TestPFSenseModule
from .test_pfsense_rule import TestPFSenseRuleModule


class TestPFSenseNatPortForwardModule(TestPFSenseModule):

    module = pfsense_nat_port_forward

    def __init__(self, *args, **kwargs):
        super(TestPFSenseNatPortForwardModule, self).__init__(*args, **kwargs)
        self.config_file = "pfsense_nat_port_forward_config.xml"
        self.pfmodule = PFSenseNatPortForwardModule
        self._drift_associated_rule = False

    def load_fixtures(self):
        """ loading data """
        super(TestPFSenseNatPortForwardModule, self).load_fixtures()
        if self._drift_associated_rule:
            tree = ET.parse(self.tmp_file)
            rule_elt = self.find_xml_tag(tree.find("filter"), dict(descr="NAT last"))
            rule_elt.find("destination/address").text = "10.255.1.99"
            rule_elt.remove(rule_elt.find("tracker"))
            tree.write(self.tmp_file, encoding="utf-8", short_empty_elements=False)

    def check_target_addr(self, params, target_elt):
        """ test the addresses definition """
        parts = params["target"].split(":")
        self.assert_xml_elt_equal(target_elt, "target", parts[0])
        if len(parts) > 1:
            self.assert_xml_elt_equal(target_elt, "local-port", parts[1])
        else:
            self.assert_xml_elt_is_none_or_empty(target_elt, "local-port")

    def get_associated_rule_elt(self, params, ruleid):
        """ check the associated rule """
        filters = dict()
        filters["interface"] = self.unalias_interface(params["interface"])
        filters["associated-rule-id"] = ruleid
        return self.assert_has_xml_tag("filter", filters)

    def check_target_elt(self, obj, target_elt, target_idx=-1):
        """ test the xml definition """
        rules_tester = TestPFSenseRuleModule()
        rules_tester.check_rule_elt_addr(obj, target_elt, "source")

        # checking destination address and ports
        rules_tester.check_rule_elt_addr(obj, target_elt, "destination")
        for address in ("source", "destination"):
            if address + "_port" in obj:
                self.assert_xml_elt_equal(target_elt, address + "/port", obj[address + "_port"])
        self.check_target_addr(obj, target_elt)
        self.check_param_equal_or_not_find(obj, target_elt, "disabled")
        self.check_param_equal_or_not_find(obj, target_elt, "nordr")
        self.check_param_equal_or_not_find(obj, target_elt, "nosync")
        self.check_param_equal_or_not_find(obj, target_elt, "natreflection", not_find_val="system-default")

        self.check_value_equal(target_elt, "interface", self.unalias_interface(obj["interface"]))
        self.check_param_equal(obj, target_elt, "ipprotocol", "inet")
        self.check_param_equal(obj, target_elt, "protocol", "tcp")
        self.check_param_equal_or_present(obj, target_elt, "local-port")

        self.check_rule_idx(obj, target_idx)
        if "associated_rule" not in obj:
            obj["associated_rule"] = "associated"

        if obj["associated_rule"] == "none" or obj["associated_rule"] == "unassociated":
            self.assert_xml_elt_is_none_or_empty(target_elt, "associated-rule-id")
        elif obj["associated_rule"] == "pass":
            self.check_value_equal(target_elt, "associated-rule-id", "pass")
        else:
            ruleid_elt = self.assert_find_xml_elt(target_elt, "associated-rule-id")
            self.assertTrue(ruleid_elt.text.startswith("nat_"))

            rule_elt = self.get_associated_rule_elt(obj, ruleid_elt.text)
            self.assertEqual(rule_elt.find("descr").text, "NAT " + obj["descr"])
            rules_tester.check_rule_elt_addr(dict(destination=obj["target"]), rule_elt, "destination")
            rules_tester.check_rule_elt_addr(obj, rule_elt, "source")
            if "source_port" in obj:
                self.assert_xml_elt_equal(rule_elt, "source/port", obj["source_port"])
            self.check_param_equal(obj, rule_elt, "protocol", "tcp")
            self.check_param_bool(obj, rule_elt, "disabled")

    def check_rule_idx(self, params, target_idx):
        """ test the xml position """
        rules_elt = self.assert_find_xml_elt(self.xml_result, "nat")

        idx = -1
        for rule_elt in rules_elt:
            if rule_elt.tag != "rule":
                continue
            idx += 1
            descr_elt = rule_elt.find("descr")
            self.assertIsNotNone(descr_elt)
            self.assertIsNotNone(descr_elt.text)
            if descr_elt.text == params["descr"]:
                self.assertEqual(idx, target_idx)
                return
        self.fail("rule not found " + str(idx))

    def get_target_elt(self, obj, absent=False, module_result=None):
        """ get the generated xml definition """
        rules_elt = self.assert_find_xml_elt(self.xml_result, "nat")

        for item in rules_elt:
            descr_elt = item.find("descr")
            if descr_elt is not None and descr_elt.text == obj["descr"]:
                return item

        return None

    ##############
    # tests
    #
    def test_nat_port_forward_create(self):
        """ test """
        obj = dict(descr="test_pf", interface="lan", source="any:443", destination="1.2.3.4:443", target="2.3.4.5:443", associated_rule="pass")
        command = (
            "create nat_port_forward 'test_pf', interface='lan', source='any:443', destination='1.2.3.4:443', target='2.3.4.5:443', associated_rule='pass'"
        )
        self.do_module_test(obj, command=command, target_idx=3)

    def test_nat_port_forward_create_range(self):
        """ test """
        obj = dict(descr="test_pf", interface="lan", source="any:9000-10000", destination="1.2.3.4:9000-10000", target="2.3.4.5:9000", associated_rule="none")
        command = (
            "create nat_port_forward 'test_pf', interface='lan', source='any:9000-10000', destination='1.2.3.4:9000-10000', "
            "target='2.3.4.5:9000', associated_rule='none'"
        )
        self.do_module_test(obj, command=command, target_idx=3)

    def test_nat_port_forward_create_associated(self):
        """ test """
        obj = dict(descr="test_pf", interface="lan", source="any:443", destination="1.2.3.4:443", target="2.3.4.5:443", associated_rule="associated")
        cmd1 = "create rule 'NAT test_pf' on 'lan', source='any:443', destination='2.3.4.5:443', protocol='tcp'"
        cmd2 = "create nat_port_forward 'test_pf', interface='lan', source='any:443', destination='1.2.3.4:443', target='2.3.4.5:443'"
        self.do_module_test(obj, command=[cmd1, cmd2], target_idx=3)

    def test_nat_port_forward_create_unassociated(self):
        """ test """
        obj = dict(descr="test_pf", interface="lan", source="any:443", destination="1.2.3.4:443", target="2.3.4.5:443", associated_rule="unassociated")
        cmd1 = "create rule 'NAT test_pf' on 'lan', source='any:443', destination='2.3.4.5:443', protocol='tcp'"
        cmd2 = (
            "create nat_port_forward 'test_pf', interface='lan', source='any:443', destination='1.2.3.4:443', target='2.3.4.5:443', "
            "associated_rule='unassociated'"
        )
        self.do_module_test(obj, command=[cmd1, cmd2], target_idx=3)

    def test_nat_port_forward_create_with_separate_ports(self):
        obj = dict(descr="test_pf", interface="lan", source="any", source_port="5000-5002",
                   destination="1.2.3.4", destination_port="8443", target="2.3.4.5:443")
        cmd1 = "create rule 'NAT test_pf' on 'lan', source='any', source_port='5000-5002', destination='2.3.4.5:443', protocol='tcp'"
        cmd2 = ("create nat_port_forward 'test_pf', interface='lan', source='any', source_port='5000-5002', "
                "destination='1.2.3.4', destination_port='8443', target='2.3.4.5:443'")
        self.do_module_test(obj, command=[cmd1, cmd2], target_idx=3)

    def test_nat_port_forward_update_separate_ports_with_associated_rule(self):
        obj = dict(descr="last", interface="wan", source="any", source_port="port_ssh",
                   destination="IP:wan", destination_port="2222", target="10.255.1.20:22", associated_rule="associated")
        cmd1 = "update rule 'NAT last' on 'wan' set source_port='port_ssh'"
        cmd2 = "update nat_port_forward 'last' set source_port='port_ssh', destination_port='2222'"
        self.do_module_test(obj, command=[cmd1, cmd2], target_idx=2)

    def test_nat_port_forward_separate_port_matches_existing_inline_port(self):
        obj = dict(descr="last", interface="wan", source="any", destination="IP:wan",
                   destination_port="22022", target="10.255.1.20:22", associated_rule="associated")
        self.do_module_test(obj, target_idx=2, changed=False)

    def test_nat_port_forward_separate_port_overrides_inline_port(self):
        obj = dict(descr="last", interface="wan", source="any", destination="IP:wan:1234",
                   destination_port="22022", target="10.255.1.20:22", associated_rule="associated")
        self.do_module_test(obj, target_idx=2, changed=False)

    def test_nat_port_forward_rejects_invalid_destination_port(self):
        obj = dict(descr="test_pf", interface="lan", source="any", destination="1.2.3.4",
                   destination_port="65536", target="2.3.4.5:443")
        self.do_module_test(obj, failed=True, msg="Cannot parse port 65536, not port number or alias")

    def test_nat_port_forward_rejects_explicit_ports_with_icmp(self):
        obj = dict(descr="test_pf", interface="lan", source="any", destination="1.2.3.4",
                   target="2.3.4.5", protocol="icmp", associated_rule="pass")
        for port_arg in ("source_port", "destination_port"):
            with self.subTest(port_arg=port_arg):
                self.do_module_test(dict(obj, **{port_arg: "443"}), failed=True,
                                    msg=f"Cannot specify {port_arg} with protocol \"icmp\".")

    def test_nat_port_forward_create_top(self):
        """ test """
        obj = dict(descr="test_pf", interface="lan", source="any:443", destination="1.2.3.4:443", target="2.3.4.5:443", associated_rule="pass", after="top")
        command = (
            "create nat_port_forward 'test_pf', interface='lan', source='any:443', destination='1.2.3.4:443', target='2.3.4.5:443', "
            "associated_rule='pass', after='top'"
        )
        self.do_module_test(obj, command=command, target_idx=0)

    def test_nat_port_forward_create_after(self):
        """ test """
        obj = dict(descr="test_pf", interface="lan", source="any:443", destination="1.2.3.4:443", target="2.3.4.5:443", associated_rule="pass", after="one")
        command = (
            "create nat_port_forward 'test_pf', interface='lan', source='any:443', destination='1.2.3.4:443', target='2.3.4.5:443', "
            "associated_rule='pass', after='one'"
        )
        self.do_module_test(obj, command=command, target_idx=1)

    def test_nat_port_forward_create_before(self):
        """ test """
        obj = dict(descr="test_pf", interface="lan", source="any:443", destination="1.2.3.4:443", target="2.3.4.5:443", associated_rule="pass", before="two")
        command = (
            "create nat_port_forward 'test_pf', interface='lan', source='any:443', destination='1.2.3.4:443', target='2.3.4.5:443', "
            "associated_rule='pass', before='two'"
        )
        self.do_module_test(obj, command=command, target_idx=1)

    def test_nat_port_forward_create_icmp(self):
        """ test """
        obj = dict(descr="test_pf", interface="wan", protocol="icmp", source="any", destination="1.2.3.4", target="2.3.4.5", associated_rule="associated")
        command = [
            "create rule 'NAT test_pf' on 'wan', source='any', destination='2.3.4.5', protocol='icmp'",
            "create nat_port_forward 'test_pf', interface='wan', protocol='icmp', source='any', destination='1.2.3.4', target='2.3.4.5'"
        ]
        self.do_module_test(obj, command=command, target_idx=3)

    def test_nat_port_forward_create_tcp_fail_no_port(self):
        """ test """
        obj = dict(descr="test_pf", interface="wan", source="any", destination="1.2.3.4", target="2.3.4.5", associated_rule="associated")
        msg = "Must specify a target port with protocol \"tcp\"."
        self.do_module_test(obj, failed=True, msg=msg)

    def test_nat_port_forward_create_icmp_fail_port(self):
        """ test """
        obj = dict(descr="test_pf", interface="wan", protocol="icmp", source="any", destination="1.2.3.4", target="2.3.4.5:443", associated_rule="associated")
        msg = "Cannot specify a target port with protocol \"icmp\"."
        self.do_module_test(obj, failed=True, msg=msg)

    def test_nat_port_forward_update_noop(self):
        """ test """
        obj = dict(descr="one", interface="wan", source="any", destination="IP:wan:22022", target="10.255.1.20:22", associated_rule="none")
        self.do_module_test(obj, target_idx=0, changed=False)

    def test_nat_port_forward_update_associated_noop(self):
        """ test """
        obj = dict(descr="last", interface="wan", source="any", destination="IP:wan:22022", target="10.255.1.20:22", associated_rule="associated")
        self.do_module_test(obj, target_idx=2, changed=False)

    def test_nat_port_forward_update_bottom(self):
        """ test """
        obj = dict(descr="one", interface="wan", source="any", destination="IP:wan:22022", target="10.255.1.20:22", associated_rule="none", before="bottom")
        command = "update nat_port_forward 'one' set before='bottom'"
        self.do_module_test(obj, command=command, target_idx=2)

    def test_nat_port_forward_update_top(self):
        """ test """
        obj = dict(descr="last", interface="wan", source="any", destination="IP:wan:22022", target="10.255.1.20:22", associated_rule="associated", after="top")
        command = "update nat_port_forward 'last' set after='top'"
        self.do_module_test(obj, command=command, target_idx=0)

    def test_nat_port_forward_update_source(self):
        """ test """
        obj = dict(descr="one", interface="wan", source="1.2.3.4", destination="IP:wan:22022", target="10.255.1.20:22", associated_rule="none")
        command = "update nat_port_forward 'one' set source='1.2.3.4'"
        self.do_module_test(obj, command=command, target_idx=0)

    def test_nat_port_forward_update_destination(self):
        """ test """
        obj = dict(descr="one", interface="wan", source="any", destination="1.2.3.4:22022", target="10.255.1.20:22", associated_rule="none")
        command = "update nat_port_forward 'one' set destination='1.2.3.4:22022'"
        self.do_module_test(obj, command=command, target_idx=0)

    def test_nat_port_forward_update_target(self):
        """ test """
        obj = dict(descr="last", interface="wan", source="any", destination="IP:wan:22022", target="10.255.1.21:22", associated_rule="associated")
        cmd1 = "update rule 'NAT last' on 'wan' set destination='10.255.1.21'"
        cmd2 = "update nat_port_forward 'last' set target='10.255.1.21:22'"
        self.do_module_test(obj, command=[cmd1, cmd2], target_idx=2)
        self.assert_xml_elt_equal(self.get_target_elt(obj), "associated-rule-id", "nat_5e03858acc6b82.92150982")

    def test_nat_port_forward_update_target_port(self):
        """ test """
        obj = dict(descr="last", interface="wan", source="any", destination="IP:wan:22022", target="10.255.1.20:2222", associated_rule="associated")
        cmd1 = "update rule 'NAT last' on 'wan' set destination_port='2222'"
        cmd2 = "update nat_port_forward 'last' set target='10.255.1.20:2222'"
        self.do_module_test(obj, command=[cmd1, cmd2], target_idx=2)
        self.assert_xml_elt_equal(self.get_target_elt(obj), "associated-rule-id", "nat_5e03858acc6b82.92150982")

    def test_nat_port_forward_update_target_range(self):
        obj = dict(descr="last", interface="wan", source="any", destination="IP:wan",
                   destination_port="22022-22025", target="10.255.1.20:22-25")
        with set_module_args(self.args_from_var(obj)):
            self.execute_module(changed=True, commands=[
                "update rule 'NAT last' on 'wan' set destination_port='22-25'",
                "update nat_port_forward 'last' set destination_port='22022-22025'",
            ])
            self.changed(changed=False)

        self.assertTrue(self.load_xml_result())
        nat_rule = self.get_target_elt(obj)
        self.assert_xml_elt_equal(nat_rule, "local-port", "22")
        self.assert_xml_elt_equal(nat_rule, "destination/port", "22022-22025")
        rule_id = nat_rule.findtext("associated-rule-id")
        self.assertEqual(rule_id, "nat_5e03858acc6b82.92150982")
        filter_rule = self.get_associated_rule_elt(obj, rule_id)
        self.assert_xml_elt_equal(filter_rule, "destination/port", "22-25")

    def test_nat_port_forward_create_legacy_target_start_with_associated_range(self):
        obj = dict(descr="test_pf", interface="lan", source="any", destination="1.2.3.4:8200-8203", target="2.3.4.5:9200")
        with set_module_args(self.args_from_var(obj)):
            self.execute_module(changed=True)

        self.assertTrue(self.load_xml_result())
        nat_rule = self.get_target_elt(obj)
        self.assert_xml_elt_equal(nat_rule, "local-port", "9200")
        filter_rule = self.get_associated_rule_elt(obj, nat_rule.findtext("associated-rule-id"))
        self.assert_xml_elt_equal(filter_rule, "destination/port", "9200-9203")

    def test_nat_port_forward_reject_target_range_length_mismatch(self):
        obj = dict(descr="test_pf", interface="lan", source="any", destination="1.2.3.4:8200-8203", target="2.3.4.5:9200-9202")
        self.do_module_test(obj, failed=True, msg="The redirect target and destination port ranges must contain the same number of ports.")

    def test_nat_port_forward_reject_descending_target_range(self):
        obj = dict(descr="test_pf", interface="lan", source="any", destination="1.2.3.4:8200-8203", target="2.3.4.5:9203-9200")
        self.do_module_test(obj, failed=True, msg='"9203-9200" is not a valid redirect target port range. Use ascending ports between 1 and 65535.')

    def test_nat_port_forward_reject_target_range_overflow(self):
        obj = dict(descr="test_pf", interface="lan", source="any", destination="1.2.3.4:8200-8203", target="2.3.4.5:65534")
        self.do_module_test(obj, failed=True, msg="The translated port range exceeds port 65535.")

    def test_nat_port_forward_update_target_ip_and_port(self):
        """ test """
        obj = dict(descr="last", interface="wan", source="any", destination="IP:wan:22022", target="10.255.1.21:2222", associated_rule="associated")
        cmd1 = "update rule 'NAT last' on 'wan' set destination='10.255.1.21', destination_port='2222'"
        cmd2 = "update nat_port_forward 'last' set target='10.255.1.21:2222'"
        self.do_module_test(obj, command=[cmd1, cmd2], target_idx=2)
        self.assert_xml_elt_equal(self.get_target_elt(obj), "associated-rule-id", "nat_5e03858acc6b82.92150982")

    def test_nat_port_forward_repair_drifted_associated_rule(self):
        """ test """
        self._drift_associated_rule = True
        try:
            obj = dict(descr="last", interface="wan", source="any", destination="IP:wan:22022", target="10.255.1.20:22", associated_rule="associated")
            command = "update rule 'NAT last' on 'wan' set destination='10.255.1.20'"
            self.do_module_test(obj, command=command, target_idx=2)
            self.assert_xml_elt_equal(self.get_target_elt(obj), "associated-rule-id", "nat_5e03858acc6b82.92150982")
        finally:
            self._drift_associated_rule = False

    def test_nat_port_forward_update_interface(self):
        """ test """
        obj = dict(descr="one", interface="vpn", source="any", destination="IP:wan:22022", target="10.255.1.20:22", associated_rule="none")
        command = "update nat_port_forward 'one' set interface='vpn'"
        self.do_module_test(obj, command=command, target_idx=0)

    def test_nat_port_forward_update_interface_associated(self):
        """ test """
        obj = dict(descr="last", interface="lan_100", source="any", destination="IP:wan:22022", target="10.255.1.20:22", associated_rule="associated")
        cmd1 = "delete rule 'NAT last' on 'wan'"
        cmd2 = "create rule 'NAT last' on 'lan_100', source='any', destination='10.255.1.20:22', protocol='tcp'"
        cmd3 = "update nat_port_forward 'last' set interface='lan_100'"
        self.do_module_test(obj, command=[cmd1, cmd2, cmd3], target_idx=2)

    def test_nat_port_forward_delete(self):
        """ test """
        obj = dict(descr="one")
        command = "delete nat_port_forward 'one'"
        self.do_module_test(obj, command=command, delete=True)

    def test_nat_port_forward_delete_associated_rule_without_interface(self):
        obj = dict(descr="last")
        commands = ["delete rule 'NAT last' on 'wan'", "delete nat_port_forward 'last'"]
        self.do_module_test(obj, command=commands, delete=True)
        self.assertIsNone(self.xml_result.find("filter/rule[descr='NAT last']"))
