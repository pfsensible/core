# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import xml.etree.ElementTree as ET

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_virtual_ip_alias, pfsense_virtual_ip_carp
from .pfsense_module import TestPFSenseModule


class TestVirtualIP(TestPFSenseModule):
    module = pfsense_virtual_ip_carp

    def setUp(self):
        super(TestVirtualIP, self).setUp()
        self.config_file = "pfsense_nat_port_forward_config.xml"
        self.stacked = False
        self.existing_mode = "carp"

    def load_fixtures(self):
        super(TestVirtualIP, self).load_fixtures()
        tree = ET.parse(self.tmp_file)
        vips = tree.getroot().find("virtualip")
        if vips is None:
            vips = ET.SubElement(tree.getroot(), "virtualip")
        fields = dict(
            mode=self.existing_mode,
            descr="Backup WAN IP",
            subnet="192.0.2.10",
            subnet_bits="24",
            type="single",
            interface="lan",
            vhid="11",
            password="previous-carp-password",
            uniqid="testcarp",
        )
        vip = ET.SubElement(vips, "vip")
        for key, value in fields.items():
            ET.SubElement(vip, key).text = value
        if self.stacked:
            child = ET.SubElement(vips, "vip")
            for key, value in dict(
                mode="ipalias", type="single", subnet="198.51.100.12", subnet_bits="29", interface="_viptestcarp", uniqid="testalias"
            ).items():
                ET.SubElement(child, key).text = value
        tree.write(self.tmp_file, encoding="utf-8", short_empty_elements=False)

    def test_delete_redacts_password_from_diff(self):
        with set_module_args(dict(address="192.0.2.10", state="absent")):
            result = self.execute_module(changed=True)
        self.assertEqual(result["diff"]["before"]["uniqid"], "testcarp")
        self.assertNotIn("password", result["diff"]["before"])
        self.assertNotIn("previous-carp-password", str(result))

    def test_reject_deleting_carp_with_stacked_alias(self):
        self.stacked = True
        with set_module_args(dict(address="192.0.2.10", state="absent")):
            self.execute_module(failed=True, msg="Move or remove the IP Aliases stacked on this CARP VIP first")
        self.phpshell.assert_not_called()

    def test_delete_does_not_target_another_mode(self):
        self.existing_mode = "ipalias"
        with set_module_args(dict(address="192.0.2.10", state="absent")):
            self.execute_module(changed=False)
        self.phpshell.assert_not_called()

    def test_stack_alias_from_different_subnet_by_carp_description(self):
        self.module = pfsense_virtual_ip_alias
        with set_module_args(dict(address="198.51.100.12/29", interface="Backup WAN IP")):
            result = self.execute_module(changed=True)
        self.assertEqual(result["diff"]["after"]["interface"], "_viptestcarp")
        self.assertEqual(result["diff"]["after"]["subnet_bits"], "29")

        self.stacked = True
        for interface in ("Backup WAN IP", "192.0.2.10", "_viptestcarp"):
            with self.subTest(interface=interface), set_module_args(dict(address="198.51.100.12/29", interface=interface)):
                self.execute_module(changed=False)

    def test_stack_alias_rejects_different_ip_address_family(self):
        self.module = pfsense_virtual_ip_alias
        with set_module_args(dict(address="2001:db8::11/64", interface="Backup WAN IP")):
            self.execute_module(failed=True, msg="A stacked IP Alias must use the same IP address family as its CARP VIP")

    def test_stack_alias_by_description_requires_carp(self):
        self.module = pfsense_virtual_ip_alias
        self.existing_mode = "ipalias"
        with set_module_args(dict(address="192.0.2.11/24", interface="Backup WAN IP")):
            self.execute_module(failed=True, msg="Backup WAN IP is not a valid interface")
