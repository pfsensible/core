# Copyright: (c) 2026, Romain Tiennot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import xml.etree.ElementTree as ET

from parameterized import parameterized

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_dhcpv6_server
from .pfsense_module import TestPFSenseModule


INTERFACES = (
    "<interfaces>"
    "<wan><if>vmx0</if><descr>WAN</descr><ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6></wan>"
    "<lan><if>vmx1</if><descr>LAN</descr><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet><ipaddrv6>track6</ipaddrv6></lan>"
    "<opt1><if>vmx2</if><descr>SERVERS</descr><ipaddr>192.168.2.1</ipaddr><subnet>24</subnet>"
    "<ipaddrv6>2001:db8:1::1</ipaddrv6><subnetv6>64</subnetv6></opt1>"
    "<opt2><if>vmx3</if><descr>GUEST</descr><ipaddr>192.168.3.1</ipaddr><subnet>24</subnet></opt2>"
    "</interfaces>"
)
# The factory settings of the LAN, disabled, with its Router Advertisement mode
FACTORY_LAN = "<lan><range><from>::1000</from><to>::2000</to></range><ramode>disabled</ramode></lan>"
SERVERS = dict(enable=True, range_from="2001:db8:1::1000", range_to="2001:db8:1::2000")
PHP = 'services_dhcpd_configure("inet6");'
UNALIGNED_PREFIX = dict(interface="opt1", prefixrange_from="2001:db8:100:1::", prefixrange_to="2001:db8:1f0::", prefixrange_length=60)


class TestPFSenseDHCPv6ServerModule(TestPFSenseModule):
    module = pfsense_dhcpv6_server

    def setUp(self):
        super(TestPFSenseDHCPv6ServerModule, self).setUp()
        self.write_config(FACTORY_LAN)

    def write_config(self, dhcpdv6):
        with open(self.tmp_file, "w") as config:
            config.write("<pfsense><version>24.0</version>{0}<dhcpdv6>{1}</dhcpdv6></pfsense>".format(INTERFACES, dhcpdv6))

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def server(self, interface):
        elt = ET.parse(self.tmp_file).find("dhcpdv6/" + interface)
        return None if elt is None else elt

    def test_create_and_repeat(self):
        params = dict(
            SERVERS,
            interface="opt1",
            dnsserver=["2001:db8::53", "2001:db8::54"],
            domain="example.com",
            domainsearchlist=["example.com", "corp.example.com"],
            defaultleasetime=7200,
            maxleasetime=86400,
        )
        result = self.run_module(changed=True, **params)
        self.assertEqual(
            result["commands"],
            [
                "create dhcpv6_server 'opt1', enable=True, range_from='2001:db8:1::1000', range_to='2001:db8:1::2000', defaultleasetime='7200', "
                "maxleasetime='86400', dnsserver='2001:db8::53 2001:db8::54', domain='example.com', domainsearchlist='example.com;corp.example.com'"
            ],
        )
        server = self.server("opt1")
        self.assertEqual(server.findtext("range/from"), "2001:db8:1::1000")
        self.assertEqual([elt.text for elt in server.findall("dnsserver")], ["2001:db8::53", "2001:db8::54"])
        self.assertIsNotNone(server.find("enable"))
        self.assertIn(PHP, self.phpshell.call_args[0][0])
        self.assertEqual(self.run_module(**params)["commands"], [])

    def test_absent_removes_the_section(self):
        result = self.run_module(changed=True, interface="lan", state="absent", _ansible_diff=True)
        self.assertEqual(result["commands"], ["delete dhcpv6_server 'lan'"])
        self.assertEqual(result["diff"]["before"]["ramode"], "disabled")
        self.assertIsNone(self.server("lan"))
        self.assertIn(PHP, self.phpshell.call_args[0][0])
        self.run_module(interface="lan", state="absent")

    def test_dynamic_dns_key_hidden(self):
        self.write_config(FACTORY_LAN.replace("<ramode>", "<ddnsdomainkey>c2VjcmV0LWtleQ==</ddnsdomainkey><ramode>"))
        result = self.run_module(changed=True, interface="lan", state="absent", _ansible_diff=True)
        self.assertNotIn("c2VjcmV0LWtleQ==", repr(result))
        self.assertEqual(result["diff"]["before"]["ddnsdomainkey"], "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER")

    def test_absent_by_description(self):
        self.run_module(changed=True, interface="LAN", state="absent")
        self.assertIsNone(self.server("lan"))

    def test_track6_suffix_range(self):
        result = self.run_module(changed=True, interface="lan", enable=True, range_from="::3000", range_to="::4000")
        self.assertEqual(result["commands"], ["update dhcpv6_server 'lan' set enable=True, range_from='::3000', range_to='::4000'"])
        self.assertEqual(self.server("lan").findtext("ramode"), "disabled")

    def test_update_keeps_omitted_options(self):
        self.run_module(changed=True, interface="lan", dnsserver=["2001:db8::53"])
        server = self.server("lan")
        self.assertEqual(server.findtext("range/to"), "::2000")
        self.assertEqual(server.findtext("dnsserver"), "2001:db8::53")
        self.assertIsNone(server.find("enable"))
        result = self.run_module(changed=True, interface="lan", dnsserver=[])
        self.assertEqual(result["commands"], ["update dhcpv6_server 'lan' set dnsserver=none"])
        self.assertIsNone(self.server("lan").find("dnsserver"))
        self.run_module(interface="lan", dnsserver=[])

    def test_disable(self):
        self.run_module(changed=True, interface="opt1", **SERVERS)
        result = self.run_module(changed=True, interface="opt1", enable=False)
        self.assertEqual(result["commands"], ["update dhcpv6_server 'opt1' set enable=False"])
        self.assertIsNone(self.server("opt1").find("enable"))
        self.assertEqual(self.server("opt1").findtext("range/from"), "2001:db8:1::1000")

    def test_prefix_delegation(self):
        self.run_module(changed=True, interface="opt1", prefixrange_from="2001:db8:100::", prefixrange_to="2001:db8:1f0::", prefixrange_length=60)
        prefixrange = self.server("opt1").find("prefixrange")
        self.assertEqual({child.tag: child.text for child in prefixrange}, {"from": "2001:db8:100::", "to": "2001:db8:1f0::", "prefixlength": "60"})

    def test_stateless_dhcp_needs_no_range(self):
        self.write_config("<opt1><ramode>stateless_dhcp</ramode></opt1>")
        self.run_module(changed=True, interface="opt1", enable=True, dnsserver=["2001:db8::53"])

    def test_check_mode(self):
        self.run_module(changed=True, interface="lan", state="absent", _ansible_check_mode=True)
        self.assertIsNotNone(self.server("lan"))
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()

    @parameterized.expand(
        [
            ("is not a valid logical interface", dict(interface="opt9", **SERVERS)),
            ("cannot be configured on the WAN", dict(interface="wan", **SERVERS)),
            ("range_from and range_to must be given together", dict(interface="opt1", range_from="2001:db8:1::1000")),
            ("range_to must be a valid IPv6 address", dict(interface="opt1", range_from="2001:db8:1::1000", range_to="192.168.2.10")),
            ("must lie in the subnet of opt1", dict(interface="opt1", range_from="2001:db8:2::1000", range_to="2001:db8:2::2000")),
            ("range_from must not be after range_to", dict(interface="opt1", range_from="2001:db8:1::2000", range_to="2001:db8:1::1000")),
            ("must be a suffix", dict(interface="lan", range_from="2001:db8:1::1000", range_to="2001:db8:1::2000")),
            ("must be the first address of a /60 prefix", UNALIGNED_PREFIX),
            ("defaultleasetime must be at least 60", dict(interface="opt1", defaultleasetime=30)),
            ("maxleasetime must be at least defaultleasetime", dict(interface="opt1", defaultleasetime=7200, maxleasetime=3600)),
            ("dnsserver takes up to 4 addresses", dict(interface="opt1", dnsserver=["2001:db8::{0}".format(n) for n in range(1, 6)])),
            ("8.8.8.8 is not one", dict(interface="opt1", dnsserver=["8.8.8.8"])),
            ("is not a valid domain name", dict(interface="opt1", domainsearchlist=["example com"])),
            ("A range is required to enable", dict(interface="opt2", enable=True)),
        ]
    )
    def test_invalid_option(self, msg, params):
        with set_module_args(params):
            self.assertIn(msg, self.failed()["msg"])
        self.assertFalse(os.path.exists(self.backup_file))
