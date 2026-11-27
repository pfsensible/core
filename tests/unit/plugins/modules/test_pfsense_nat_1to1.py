# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from pathlib import Path
import xml.etree.ElementTree as ET

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_nat_1to1
from .pfsense_module import TestPFSenseModule


class TestPFSenseNat1to1Module(TestPFSenseModule):
    module = pfsense_nat_1to1
    rule = {"descr": "Web server's mapping", "source": "192.168.10.8", "external": "192.0.2.8"}

    def setUp(self):
        super(TestPFSenseNat1to1Module, self).setUp()
        self.config = Path(self.tmp_file)
        self.config.write_text(
            "<pfsense><version>24.0</version>"
            "<interfaces><wan><descr>WAN</descr></wan><lan><descr>Inside</descr></lan></interfaces>"
            "<aliases><alias><name>RemotePeers</name><type>network</type></alias></aliases>"
            "</pfsense>",
            encoding="utf-8",
        )

    def apply(self, *, changed=True, **options):
        with set_module_args(dict(self.rule, **options)):
            return self.changed(changed)

    def saved_rule(self):
        return ET.parse(self.config).find("nat/onetoone")

    def test_create_and_reapply_without_nat_section(self):
        result = self.apply()
        saved = self.saved_rule()
        self.assertEqual(saved.findtext("descr"), self.rule["descr"])
        self.assertEqual(saved.findtext("interface"), "wan")
        self.assertEqual(saved.findtext("ipprotocol"), "inet")
        self.assertEqual(saved.findtext("external"), "192.0.2.8")
        self.assertEqual(saved.findtext("source/address"), "192.168.10.8")
        self.assertIsNotNone(saved.find("destination/any"))
        self.assertTrue(result["commands"][0].startswith("create nat_1to1 "))
        self.assertIn("filter_configure()", self.phpshell.call_args[0][0])
        before = self.config.read_bytes()
        self.apply(changed=False, source="192.168.10.8/32", destination="any")
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.phpshell.call_count, 1)

    def test_update_nested_fields_and_clear_options(self):
        self.apply(natreflection="disable", disabled=True, nobinat=True, destination="!RemotePeers")
        saved = self.saved_rule()
        self.assertIsNotNone(saved.find("disabled"))
        self.assertIsNotNone(saved.find("nobinat"))
        self.assertIsNotNone(saved.find("destination/not"))
        self.assertEqual(saved.findtext("destination/address"), "RemotePeers")
        self.assertEqual(saved.findtext("natreflection"), "disable")

        result = self.apply(interface="Inside", source="192.168.10.8/24", external="192.0.2.0")
        self.assertTrue(result["commands"][0].startswith("update nat_1to1 "))
        root = ET.parse(self.config)
        self.assertEqual(len(root.findall("nat/onetoone")), 1)
        saved = root.find("nat/onetoone")
        self.assertEqual(saved.findtext("interface"), "lan")
        self.assertEqual(saved.findtext("source/address"), "192.168.10.0/24")
        self.assertEqual([child.tag for child in saved.find("destination")], ["any"])
        for flag in ("disabled", "nobinat", "natreflection"):
            self.assertIsNone(saved.find(flag))
        self.apply(changed=False, interface="lan", source="192.168.10.0/24", external="192.0.2.0")

    def test_ipv6_and_interface_address(self):
        self.apply(ipprotocol="inet6", external="IP:WAN", source="2001:0db8:1::1/128", destination="!2001:db8:2::/64")
        saved = self.saved_rule()
        self.assertEqual(saved.findtext("ipprotocol"), "inet6")
        self.assertEqual(saved.findtext("external"), "wanip")
        self.assertEqual(saved.findtext("source/address"), "2001:db8:1::1")
        self.assertEqual(saved.findtext("destination/address"), "2001:db8:2::/64")
        self.assertIsNotNone(saved.find("destination/not"))

        self.apply(source="IP:Inside", destination="NET:WAN")
        saved = self.saved_rule()
        self.assertEqual([child.tag for child in saved.find("source")], ["network"])
        self.assertEqual([child.tag for child in saved.find("destination")], ["network"])
        self.assertEqual(saved.findtext("source/network"), "lanip")
        self.assertEqual(saved.findtext("destination/network"), "wan")

    def test_preview_and_delete_by_description(self):
        before = self.config.read_bytes()
        self.apply(_ansible_check_mode=True)
        self.assertEqual(self.config.read_bytes(), before)
        self.phpshell.assert_not_called()
        self.apply()
        before = self.config.read_bytes()
        delete = {"descr": self.rule["descr"], "state": "absent"}
        with set_module_args(dict(delete, _ansible_check_mode=True)):
            self.changed(True)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.phpshell.call_count, 1)
        with set_module_args(delete):
            self.changed(True)
        self.assertIsNone(self.saved_rule())
        with set_module_args(delete):
            self.changed(False)
        self.assertEqual(self.phpshell.call_count, 2)

    def test_duplicate_description_fails_without_writing(self):
        self.apply()
        root = ET.parse(self.config)
        root.find("nat").append(root.find("nat/onetoone"))
        root.write(self.config)
        before = self.config.read_bytes()
        with set_module_args({"descr": self.rule["descr"], "state": "absent"}):
            self.assertIn("Found multiple 1:1 NAT rules", self.failed()["msg"])
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.phpshell.call_count, 1)

    def test_invalid_arguments_leave_config_untouched(self):
        before = self.config.read_bytes()
        cases = (
            ({"descr": " "}, "descr must contain a rule name"),
            ({"external": None}, "external"),
            ({"source": None}, "source"),
            ({"external": "RemotePeers"}, "external must be an IP address"),
            ({"external": "2001:db8::1"}, "external must use the address family"),
            ({"source": "2001:db8::1"}, "source must use the address family"),
            ({"destination": "2001:db8::1"}, "destination must use the address family"),
            ({"source": "RemotePeers"}, "source must specify an IP address"),
            ({"source": "192.168.10.8:80"}, "source must specify an address without a port"),
            ({"destination": "IP:WAN:80"}, "destination must specify an address without a port"),
            ({"destination": "!"}, "destination must specify a valid address"),
            ({"interface": "missing"}, "missing is not a valid interface"),
        )
        for options, message in cases:
            with self.subTest(options=options), set_module_args(dict(self.rule, **options)):
                self.assertIn(message, self.failed()["msg"])
        self.assertEqual(self.config.read_bytes(), before)
        self.phpshell.assert_not_called()
