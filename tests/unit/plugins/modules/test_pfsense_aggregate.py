# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest
import sys
import xml.etree.ElementTree as ET

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_aggregate
from .pfsense_module import TestPFSenseModule


class TestPFSenseAggregateModule(TestPFSenseModule):
    module = pfsense_aggregate

    def __init__(self, *args, **kwargs):
        super(TestPFSenseAggregateModule, self).__init__(*args, **kwargs)
        self.config_file = "pfsense_aggregate_config.xml"

    def assert_find_alias(self, alias):
        """test if an alias exist"""
        self.load_xml_result()
        parent_tag = self.xml_result.find("aliases")
        if parent_tag is None:
            self.fail("Unable to find tag aliases")

        tag = self.find_xml_tag(parent_tag, dict(name=alias))
        if tag is None:
            self.fail("Alias not found: " + alias)

    def assert_not_find_alias(self, alias):
        """test if an alias does not exist"""
        self.load_xml_result()
        parent_tag = self.xml_result.find("aliases")
        if parent_tag is None:
            self.fail("Unable to find tag aliases")

        tag = self.find_xml_tag(parent_tag, dict(name=alias))
        if tag is not None:
            self.fail("Alias found: " + alias)

    def assert_find_rule(self, rule, interface):
        """test if a rule exist on interface"""
        self.load_xml_result()
        parent_tag = self.xml_result.find("filter")
        if parent_tag is None:
            self.fail("Unable to find tag filter")

        tag = self.find_xml_tag(parent_tag, dict(descr=rule, interface=interface))
        if tag is None:
            self.fail("Rule not found: " + rule)

    def assert_not_find_rule(self, rule, interface):
        """test if a rule does not exist on interface"""
        self.load_xml_result()
        parent_tag = self.xml_result.find("filter")
        if parent_tag is None:
            self.fail("Unable to find tag filter")

        tag = self.find_xml_tag(parent_tag, dict(descr=rule, interface=interface))
        if tag is not None:
            self.fail("Rule found: " + rule + " on " + interface)

    def assert_find_rule_separator(self, separator, interface):
        """test if a rule separator exist on interface"""
        self.load_xml_result()
        interface = self.unalias_interface(interface)
        parent_tag = self.xml_result.find("filter")
        if parent_tag is None:
            self.fail("Unable to find tag filter")

        separators_elt = parent_tag.find("separator")
        if parent_tag is None:
            self.fail("Unable to find tag separator")

        interface_elt = separators_elt.find(interface)
        if parent_tag is None:
            self.fail("Unable to find tag " + interface)

        tag = self.find_xml_tag(interface_elt, dict(text=separator))
        if tag is None:
            self.fail("Separator not found: " + separator)

    def assert_not_find_rule_separator(self, separator, interface):
        """test if a rule separator dost exist on interface"""
        self.load_xml_result()
        interface = self.unalias_interface(interface)
        parent_tag = self.xml_result.find("filter")
        if parent_tag is None:
            self.fail("Unable to find tag filter")

        separators_elt = parent_tag.find("separator")
        if parent_tag is None:
            self.fail("Unable to find tag separator")

        interface_elt = separators_elt.find(interface)
        if parent_tag is None:
            self.fail("Unable to find tag " + interface)

        tag = self.find_xml_tag(interface_elt, dict(text=separator))
        if tag is not None:
            self.fail("Separator found: " + separator)

    def assert_find_vlan(self, interface, vlan_id):
        """test if a vlan exist"""
        self.load_xml_result()
        parent_tag = self.xml_result.find("vlans")
        if parent_tag is None:
            self.fail("Unable to find tag vlans")

        elt_filter = {}
        elt_filter["if"] = interface
        elt_filter["tag"] = vlan_id
        tag = self.find_xml_tag(parent_tag, elt_filter)
        if tag is None:
            self.fail("Vlan not found: {0}.{1}".format(interface, vlan_id))

    def assert_not_find_vlan(self, interface, vlan_id):
        """test if an vlan does not exist"""
        self.load_xml_result()
        parent_tag = self.xml_result.find("vlans")
        if parent_tag is None:
            self.fail("Unable to find tag vlans")

        elt_filter = {}
        elt_filter["if"] = interface
        elt_filter["vlan_id"] = vlan_id
        tag = self.find_xml_tag(parent_tag, elt_filter)
        if tag is not None:
            self.fail("Vlan found: {0}.{1}".format(interface, vlan_id))

    ############
    # as we rely on sub modules for modifying the xml
    # we dont perform extensive checks on the xml modifications
    # we just test if elements are created or deleted, and the respective output
    def test_aggregate_aliases(self):
        """test creation of a some aliases"""
        args = dict(
            purge_aliases=False,
            aggregated_aliases=[
                dict(name="one_host", type="host", address="10.9.8.7"),
                dict(name="another_host", type="host", address="10.9.8.6"),
                dict(name="one_server", type="host", address="192.168.1.165", descr="", detail=""),
                dict(name="port_ssh", type="port", address="2222"),
                dict(name="port_dns", state="absent"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            result_aliases = []
            result_aliases.append("create alias 'one_host', type='host', address='10.9.8.7'")
            result_aliases.append("create alias 'another_host', type='host', address='10.9.8.6'")
            result_aliases.append("update alias 'port_ssh' set address='2222'")
            result_aliases.append("delete alias 'port_dns'")

            self.assertEqual(result["result_aliases"], result_aliases)
            self.assert_find_alias("one_host")
            self.assert_find_alias("another_host")
            self.assert_find_alias("one_server")
            self.assert_find_alias("port_ssh")
            self.assert_find_alias("port_http")
            self.assert_not_find_alias("port_dns")

    def test_aggregate_aliases_checkmode(self):
        """test creation of a some aliases with check_mode"""
        args = dict(
            purge_aliases=False,
            aggregated_aliases=[
                dict(name="one_host", type="host", address="10.9.8.7"),
                dict(name="another_host", type="host", address="10.9.8.6"),
                dict(name="one_server", type="host", address="192.168.1.165", descr="", detail=""),
                dict(name="port_ssh", type="port", address="2222"),
                dict(name="port_dns", state="absent"),
            ],
            _ansible_check_mode=True,
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            result_aliases = []
            result_aliases.append("create alias 'one_host', type='host', address='10.9.8.7'")
            result_aliases.append("create alias 'another_host', type='host', address='10.9.8.6'")
            result_aliases.append("update alias 'port_ssh' set address='2222'")
            result_aliases.append("delete alias 'port_dns'")

            self.assertEqual(result["result_aliases"], result_aliases)
            self.assertFalse(self.load_xml_result())

    def test_aggregate_interface_gateway(self):
        self.php.return_value = {"vmx0": {}}
        args = dict(
            aggregated_interfaces=[
                dict(
                    descr="WAN",
                    interface="vmx0",
                    enable=True,
                    ipv4_type="static",
                    ipv4_address="192.0.2.10",
                    ipv4_gateway="UPSTREAM_GW",
                    ipv4_gateway_address="192.0.2.1",
                ),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
        self.assertIn("create gateway 'UPSTREAM_GW', interface='WAN', gateway='192.0.2.1'", result["result_interfaces"])
        self.assert_xml_elt_dict("gateways", {"name": "UPSTREAM_GW"}, {"interface": "wan", "gateway": "192.0.2.1"})
        self.assertEqual(self.xml_result.findtext("interfaces/wan/gateway"), "UPSTREAM_GW")

    def test_aggregate_aliases_purge(self):
        """test creation of a some aliases with purge"""
        args = dict(
            purge_aliases=True,
            purge_rules=False,
            ignored_aliases=["port_http"],
            aggregated_aliases=[
                dict(name="one_host", type="host", address="10.9.8.7"),
                dict(name="another_host", type="host", address="10.9.8.6"),
                dict(name="one_server", type="host", address="192.168.1.165", descr="", detail=""),
                dict(name="port_ssh", type="port", address="2222"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            result_aliases = []
            result_aliases.append("create alias 'one_host', type='host', address='10.9.8.7'")
            result_aliases.append("create alias 'another_host', type='host', address='10.9.8.6'")
            result_aliases.append("update alias 'port_ssh' set address='2222'")
            result_aliases.append("delete alias 'port_dns'")

            self.assertEqual(result["result_aliases"], result_aliases)
            self.assert_find_alias("one_host")
            self.assert_find_alias("another_host")
            self.assert_find_alias("one_server")
            self.assert_find_alias("port_ssh")
            self.assert_find_alias("port_http")
            self.assert_not_find_alias("port_dns")

    def test_aggregate_purge_rejects_alias_in_use(self):
        """test that an alias purge fails when a firewall rule still uses the alias"""
        with set_module_args(dict(aggregated_aliases=[], purge_aliases=True, ignored_aliases=["port_ssh"])):
            self.execute_module(failed=True, msg="Alias 'port_http' is in use by filter/rule 'any2any_http' (destination/port).")
            self.assertFalse(self.load_xml_result())

    def test_aggregate_removes_alias_with_its_references(self):
        """test removal of an alias while deleting or updating the rules that use it"""
        args = dict(
            aggregated_aliases=[dict(name="port_http", state="absent")],
            aggregated_rules=[
                dict(name="any2any_http", state="absent", interface="lan"),
                dict(name="any2any_http", source="any", destination="any", destination_port="8080", interface="vpn", protocol="tcp"),
            ],
        )
        with set_module_args(args):
            self.execute_module(changed=True)
            self.assert_not_find_alias("port_http")
            self.assert_not_find_rule("any2any_http", "lan")
            self.assert_find_rule("any2any_http", "opt1")

    def test_aggregate_rules(self):
        """test creation of a some rules"""
        args = dict(
            purge_rules=False,
            aggregated_rules=[
                dict(name="one_rule", source="any", destination="any", interface="lan"),
                dict(name="any2any_ssh", source="any", destination="any:2222", interface="lan", protocol="tcp"),
                dict(name="any2any_http", source="any", destination="any:8080", interface="vpn", protocol="tcp"),
                dict(name="any2any_ssh", state="absent", interface="vpn"),
            ],
        )
        with set_module_args(args):
            self.execute_module(changed=True)
            self.assert_find_rule("one_rule", "lan")
            self.assert_find_rule("any2any_ssh", "lan")
            self.assert_find_rule("any2any_http", "lan")
            self.assert_find_rule("any2any_https", "lan")
            self.assert_not_find_rule("any2any_ssh", "opt1")
            self.assert_find_rule("any2any_http", "opt1")
            self.assert_find_rule("any2any_https", "opt1")

    def test_aggregate_rules_purge(self):
        """test creation of a some rules with purge"""
        args = dict(
            purge_rules=True,
            aggregated_rules=[
                dict(name="one_rule", source="any", destination="any", interface="lan"),
                dict(name="any2any_ssh", source="any", destination="any:2222", interface="lan", protocol="tcp"),
                dict(name="any2any_http", source="any", destination="any:8080", interface="vpn", protocol="tcp"),
                dict(name="any2any_ssh", state="absent", interface="vpn"),
            ],
        )
        with set_module_args(args):
            self.execute_module(changed=True)
            self.assert_find_rule("one_rule", "lan")
            self.assert_find_rule("any2any_ssh", "lan")
            self.assert_not_find_rule("any2any_http", "lan")
            self.assert_not_find_rule("any2any_https", "lan")
            self.assert_not_find_rule("any2any_ssh", "opt1")
            self.assert_find_rule("any2any_http", "opt1")
            self.assert_not_find_rule("any2any_https", "opt1")

    def test_aggregate_separators(self):
        """test creation of a some separators"""
        args = dict(
            purge_rule_separators=False,
            aggregated_rule_separators=[
                dict(name="one_separator", interface="lan"),
                dict(name="another_separator", interface="lan_100"),
                dict(name="another_test_separator", interface="lan", state="absent"),
                dict(name="test_separator", interface="lan", before="bottom", color="warning"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            result_separators = []
            result_separators.append("create rule_separator 'one_separator' on 'lan', color='info'")
            result_separators.append("create rule_separator 'another_separator' on 'lan_100', color='info'")
            result_separators.append("delete rule_separator 'another_test_separator' on 'lan'")
            result_separators.append("update rule_separator 'test_separator' on 'lan' set color='warning', before='bottom'")

            self.assertEqual(result["result_rule_separators"], result_separators)
            self.assert_find_rule_separator("one_separator", "lan")
            self.assert_find_rule_separator("another_separator", "lan_100")
            self.assert_not_find_rule_separator("another_test_separator", "lan")
            self.assert_find_rule_separator("test_separator", "lan")

    def test_aggregate_separators_purge(self):
        """test creation of a some separators with purge"""
        args = dict(
            purge_rule_separators=True,
            aggregated_rule_separators=[
                dict(name="one_separator", interface="lan"),
                dict(name="another_separator", interface="lan_100"),
                dict(name="another_test_separator", interface="lan", state="absent"),
                dict(name="test_separator", interface="lan", before="bottom", color="warning"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            result_separators = []
            result_separators.append("create rule_separator 'one_separator' on 'lan', color='info'")
            result_separators.append("create rule_separator 'another_separator' on 'lan_100', color='info'")
            result_separators.append("delete rule_separator 'another_test_separator' on 'lan'")
            result_separators.append("update rule_separator 'test_separator' on 'lan' set color='warning', before='bottom'")
            result_separators.append("delete rule_separator 'test_separator' on 'wan'")
            result_separators.append("delete rule_separator 'last_test_separator' on 'lan'")
            result_separators.append("delete rule_separator 'test_sep_floating' on 'floating'")

            self.assertEqual(result["result_rule_separators"], result_separators)
            self.assert_find_rule_separator("one_separator", "lan")
            self.assert_find_rule_separator("another_separator", "lan_100")
            self.assert_not_find_rule_separator("another_test_separator", "lan")
            self.assert_find_rule_separator("test_separator", "lan")
            self.assert_not_find_rule_separator("last_test_separator", "lan")
            self.assert_not_find_rule_separator("test_sep_floating", "floatingrules")

    def test_aggregate_nat_outbound(self):
        """test creation of some nat outbound"""
        args = dict(
            purge_nat_outbounds=True,
            aggregated_nat_outbounds=[
                dict(descr="snat 1", source="192.168.100.0/24", destination="1.1.1.0/24", interface="lan", staticnatport=True),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            result_nat_outbounds = []
            result_nat_outbounds.append("delete nat_outbound 'None'")
            result_nat_outbounds.append(
                "create nat_outbound 'snat 1', interface='lan', source='192.168.100.0/24', destination='1.1.1.0/24', staticnatport=True"
            )

            self.assertEqual(result["result_nat_outbounds"], result_nat_outbounds)

    def test_aggregate_vlans(self):
        """test creation of some vlans"""
        args = dict(
            purge_vlans=False,
            aggregated_vlans=[
                dict(vlan_id=100, interface="vmx0", descr="voice"),
                dict(vlan_id=1200, interface="vmx1", state="absent"),
                dict(vlan_id=101, interface="vmx1", descr="printers"),
                dict(vlan_id=102, interface="vmx2", descr="users"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            result_aliases = []
            result_aliases.append("update vlan 'vmx0.100' set descr='voice'")
            result_aliases.append("delete vlan 'vmx1.1200'")
            result_aliases.append("create vlan 'vmx1.101', descr='printers', priority=''")
            result_aliases.append("create vlan 'vmx2.102', descr='users', priority=''")

            self.assertEqual(result["result_vlans"], result_aliases)
            self.assert_find_vlan("vmx0", "100")
            self.assert_not_find_vlan("vmx1", "1200")
            self.assert_find_vlan("vmx1", "101")
            self.assert_find_vlan("vmx2", "102")

    def test_aggregate_vlans_with_purge(self):
        """test creation of some vlans with purge"""
        args = dict(
            purge_vlans=True,
            aggregated_vlans=[
                dict(vlan_id=1100, interface="vmx1"),
                dict(vlan_id=1200, interface="vmx1", state="absent"),
                dict(vlan_id=101, interface="vmx1", descr="printers"),
                dict(vlan_id=102, interface="vmx2", descr="users"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            result_aliases = []
            result_aliases.append("delete vlan 'vmx1.1200'")
            result_aliases.append("create vlan 'vmx1.101', descr='printers', priority=''")
            result_aliases.append("create vlan 'vmx2.102', descr='users', priority=''")
            result_aliases.append("delete vlan 'vmx0.100'")

            self.assertEqual(result["result_vlans"], result_aliases)
            self.assert_not_find_vlan("vmx1", "1200")
            self.assert_find_vlan("vmx1", "101")
            self.assert_find_vlan("vmx2", "102")
            self.assert_not_find_vlan("vmx0", "100")


class TestPFSenseAggregateDHCPStaticModule(TestPFSenseModule):
    module = pfsense_aggregate

    def __init__(self, *args, **kwargs):
        super(TestPFSenseAggregateDHCPStaticModule, self).__init__(*args, **kwargs)
        self.config_file = "pfsense_dhcp_static_config.xml"
        self.edit_fixture = None

    def load_fixtures(self):
        """loading data, then applying the test's edit_fixture(root) if any"""
        super(TestPFSenseAggregateDHCPStaticModule, self).load_fixtures()
        if self.edit_fixture is not None:
            tree = ET.parse(self.tmp_file)
            self.edit_fixture(tree.getroot())
            tree.write(self.tmp_file, encoding="utf-8", short_empty_elements=False)

    @staticmethod
    def add_staticmap(root, netif, **fields):
        """add a static map with fields to the DHCP server of netif, creating the server if needed"""
        dhcp_elt = root.find("dhcpd").find(netif)
        if dhcp_elt is None:
            dhcp_elt = ET.SubElement(root.find("dhcpd"), netif)
            ET.SubElement(dhcp_elt, "enable")
        staticmap_elt = ET.SubElement(dhcp_elt, "staticmap")
        for key, value in fields.items():
            ET.SubElement(staticmap_elt, key).text = value

    def find_staticmap(self, netif, name=None, mac=None):
        """return the static map on netif with cid name (and mac if given), or None"""
        self.load_xml_result()
        elt_filter = dict(cid=name) if mac is None else dict(mac=mac) if name is None else dict(cid=name, mac=mac)
        return self.find_xml_tag(self.assert_find_xml_elt(self.xml_result, "dhcpd").find(netif), elt_filter)

    def assert_dhcpd_reloaded(self):
        """test that the DHCP server was reloaded in the single update command"""
        self.phpshell.assert_called_once()
        self.assertIn("services_dhcpd_configure()", self.phpshell.call_args[0][0])

    def test_aggregate_dhcp_statics(self):
        """test creation of static maps on several interfaces in one call"""
        args = dict(
            aggregated_dhcp_statics=[
                dict(name="test_entry", macaddr="ab:ab:ab:ab:ab:ac", ipaddr="10.0.0.101", netif="pub"),
                dict(name="other_entry", macaddr="ab:ab:ab:ab:ab:ad", ipaddr="10.10.0.101", netif="opt2"),
            ]
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertEqual(
                result["result_dhcp_statics"],
                [
                    "create dhcp_static 'test_entry', macaddr='ab:ab:ab:ab:ab:ac', ipaddr='10.0.0.101'",
                    "create dhcp_static 'other_entry', macaddr='ab:ab:ab:ab:ab:ad', ipaddr='10.10.0.101'",
                ],
            )
            self.assertIsNotNone(self.find_staticmap("opt1", "test_entry"))
            self.assertIsNotNone(self.find_staticmap("opt2", "other_entry"))
            self.assertIsNotNone(self.find_staticmap("opt1", "dhcphostid"))
            self.assert_dhcpd_reloaded()

    def test_aggregate_dhcp_statics_update(self):
        """test update of an existing static map"""
        args = dict(
            aggregated_dhcp_statics=[
                dict(name="dhcphostid", macaddr="ab:ab:ab:ab:ab:ab", ipaddr="10.0.0.110", hostname="dhcphostname", netif="opt1"),
            ]
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertEqual(result["result_dhcp_statics"], ["update dhcp_static 'dhcphostid' set ipaddr='10.0.0.110'"])
            self.assertEqual(self.find_staticmap("opt1", "dhcphostid").findtext("ipaddr"), "10.0.0.110")
            self.assert_dhcpd_reloaded()

    def test_aggregate_dhcp_statics_delete(self):
        """test deletion of a static map"""
        args = dict(aggregated_dhcp_statics=[dict(name="dhcphostid", netif="opt1", state="absent")])
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertEqual(result["result_dhcp_statics"], ["delete dhcp_static 'dhcphostid' on 'opt1'"])
            self.assertIsNone(self.find_staticmap("opt1", "dhcphostid"))
            self.assert_dhcpd_reloaded()

    def test_aggregate_dhcp_statics_unchanged(self):
        """test that an existing static map declared as is reports no change"""
        args = dict(
            aggregated_dhcp_statics=[
                dict(name="dhcphostid", macaddr="ab:ab:ab:ab:ab:ab", ipaddr="10.0.0.100", hostname="dhcphostname", netif="opt1"),
            ]
        )
        with set_module_args(args):
            result = self.execute_module(changed=False)
            self.assertEqual(result["result_dhcp_statics"], [])
            self.assertFalse(self.load_xml_result())
            self.phpshell.assert_not_called()

    def test_aggregate_dhcp_statics_checkmode(self):
        """test creation of a static map with check_mode"""
        args = dict(
            aggregated_dhcp_statics=[dict(name="test_entry", macaddr="ab:ab:ab:ab:ab:ac", ipaddr="10.0.0.101", netif="opt1")],
            _ansible_check_mode=True,
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertEqual(result["result_dhcp_statics"], ["create dhcp_static 'test_entry', macaddr='ab:ab:ab:ab:ab:ac', ipaddr='10.0.0.101'"])
            self.assertFalse(self.load_xml_result())
            self.phpshell.assert_not_called()

    def test_aggregate_dhcp_statics_purge(self):
        """test that purge deletes the static maps not declared"""
        args = dict(
            purge_dhcp_statics=True,
            aggregated_dhcp_statics=[dict(name="other_entry", macaddr="ab:ab:ab:ab:ab:ad", ipaddr="10.10.0.101", netif="opt2")],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertEqual(
                result["result_dhcp_statics"],
                [
                    "create dhcp_static 'other_entry', macaddr='ab:ab:ab:ab:ab:ad', ipaddr='10.10.0.101'",
                    "delete dhcp_static 'dhcphostid' on 'opt1'",
                ],
            )
            self.assertIsNone(self.find_staticmap("opt1", "dhcphostid"))
            self.assertIsNotNone(self.find_staticmap("opt2", "other_entry"))

    def test_aggregate_dhcp_statics_purge_two_on_same_netif(self):
        """test that purge keeps every declared static map of an interface"""
        args = dict(
            purge_dhcp_statics=True,
            aggregated_dhcp_statics=[
                dict(name="first", macaddr="ab:ab:ab:ab:ab:01", ipaddr="10.0.0.101", netif="opt1"),
                dict(name="second", macaddr="ab:ab:ab:ab:ab:02", ipaddr="10.0.0.102", netif="opt1"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertEqual(
                result["result_dhcp_statics"],
                [
                    "create dhcp_static 'first', macaddr='ab:ab:ab:ab:ab:01', ipaddr='10.0.0.101'",
                    "create dhcp_static 'second', macaddr='ab:ab:ab:ab:ab:02', ipaddr='10.0.0.102'",
                    "delete dhcp_static 'dhcphostid' on 'opt1'",
                ],
            )
            self.assertIsNotNone(self.find_staticmap("opt1", "first"))
            self.assertIsNotNone(self.find_staticmap("opt1", "second"))

    def test_aggregate_dhcp_statics_purge_converged(self):
        """test that purge over an already converged list reports no change"""
        args = dict(
            purge_dhcp_statics=True,
            aggregated_dhcp_statics=[
                dict(name="dhcphostid", macaddr="ab:ab:ab:ab:ab:ab", ipaddr="10.0.0.100", hostname="dhcphostname", netif="opt1"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=False)
            self.assertEqual(result["result_dhcp_statics"], [])
            self.phpshell.assert_not_called()

    def test_aggregate_dhcp_statics_purge_absent(self):
        """test that an absent item combined with purge is deleted once"""
        args = dict(
            purge_dhcp_statics=True,
            aggregated_dhcp_statics=[
                dict(name="dhcphostid", netif="opt1", state="absent"),
                dict(name="other_entry", macaddr="ab:ab:ab:ab:ab:ad", ipaddr="10.10.0.101", netif="opt2"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertEqual(
                result["result_dhcp_statics"],
                [
                    "delete dhcp_static 'dhcphostid' on 'opt1'",
                    "create dhcp_static 'other_entry', macaddr='ab:ab:ab:ab:ab:ad', ipaddr='10.10.0.101'",
                ],
            )
            self.assertIsNone(self.find_staticmap("opt1", "dhcphostid"))

    def test_aggregate_dhcp_statics_purge_mac_only(self):
        """test that purge deletes a static map without client identifier, naming it by its MAC"""
        self.edit_fixture = lambda root: self.add_staticmap(root, "opt2", mac="ab:ab:ab:ab:ab:ae", ipaddr="10.10.0.102")
        args = dict(
            purge_dhcp_statics=True,
            aggregated_dhcp_statics=[
                dict(name="dhcphostid", macaddr="ab:ab:ab:ab:ab:ab", ipaddr="10.0.0.100", hostname="dhcphostname", netif="opt1"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertEqual(result["result_dhcp_statics"], ["delete dhcp_static 'ab:ab:ab:ab:ab:ae' on 'opt2'"])
            self.assertIsNone(self.find_staticmap("opt2", mac="ab:ab:ab:ab:ab:ae"))
            self.assert_dhcpd_reloaded()

    def test_aggregate_dhcp_statics_purge_disabled_server(self):
        """test that purge leaves the static maps of a disabled DHCP server alone"""
        self.edit_fixture = lambda root: self.add_staticmap(root, "lan", cid="lan_entry", mac="ab:ab:ab:ab:ab:af", ipaddr="192.168.1.10")
        args = dict(purge_dhcp_statics=True, aggregated_dhcp_statics=[])
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertEqual(result["result_dhcp_statics"], ["delete dhcp_static 'dhcphostid' on 'opt1'"])
            self.assertIsNotNone(self.find_staticmap("lan", "lan_entry"))

    def test_aggregate_dhcp_statics_purge_unmanaged_server(self):
        """test that purge skips enabled DHCP servers on missing or unaddressed interfaces"""

        def edit(root):
            self.add_staticmap(root, "opt9", cid="stale_entry", mac="ab:ab:ab:ab:ab:b0")
            self.add_staticmap(root, "opt5", cid="dhcp_wan_entry", mac="ab:ab:ab:ab:ab:b1")

        self.edit_fixture = edit
        args = dict(purge_dhcp_statics=True, aggregated_dhcp_statics=[])
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertEqual(result["result_dhcp_statics"], ["delete dhcp_static 'dhcphostid' on 'opt1'"])
            self.assertIsNotNone(self.find_staticmap("opt9", "stale_entry"))
            self.assertIsNotNone(self.find_staticmap("opt5", "dhcp_wan_entry"))

    def test_aggregate_dhcp_statics_purge_no_dhcpd(self):
        """test that purge without any DHCP server configuration does nothing"""
        self.edit_fixture = lambda root: root.remove(root.find("dhcpd"))
        args = dict(purge_dhcp_statics=True, aggregated_dhcp_statics=[])
        with set_module_args(args):
            result = self.execute_module(changed=False)
            self.assertEqual(result["result_dhcp_statics"], [])

    def test_aggregate_dhcp_statics_purge_display_name_collision(self):
        """test that purge deletes the undeclared static map when an interface description matches another interface name"""

        def edit(root):
            root.find("interfaces/opt2/descr").text = "OPT1"
            self.add_staticmap(root, "opt1", cid="dup", mac="ab:ab:ab:ab:ab:b2", ipaddr="10.0.0.102")
            self.add_staticmap(root, "opt2", cid="dup", mac="ab:ab:ab:ab:ab:b2", ipaddr="10.10.0.102")

        self.edit_fixture = edit
        args = dict(
            purge_dhcp_statics=True,
            aggregated_dhcp_statics=[
                dict(name="dup", macaddr="ab:ab:ab:ab:ab:b2", ipaddr="10.10.0.102", netif="opt2"),
            ],
        )
        with set_module_args(args):
            result = self.execute_module(changed=True)
            self.assertIn("delete dhcp_static 'dup' on 'opt1'", result["result_dhcp_statics"])
            self.assertIsNone(self.find_staticmap("opt1", "dup"))
            self.assertIsNone(self.find_staticmap("opt1", "dhcphostid"))
            self.assertIsNotNone(self.find_staticmap("opt2", "dup"))
