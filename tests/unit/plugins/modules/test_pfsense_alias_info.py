# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_alias_info

from .pfsense_module import TestPFSenseModule


class TestPFSenseAliasInfoModule(TestPFSenseModule):
    module = pfsense_alias_info

    def test_reports_aliases_with_usage_and_optional_filtering(self):
        config = """<pfsense>
          <version>24.0</version>
          <aliases>
            <alias><name>idle</name><type>network</type><address>idle_child</address><descr>Old group</descr></alias>
            <alias><name>used</name><type>network</type><address>used_child</address></alias>
            <alias><name>used_child</name><type>network</type><address>used used_leaf</address></alias>
            <alias><name>used_leaf</name><type>host</type><address>192.0.2.1</address></alias>
            <alias><name>idle_child</name><type>host</type><address>idle 192.0.2.2</address><detail>||old entry</detail></alias>
            <alias><name>forward_ports</name><type>port</type><address>8080</address></alias>
            <alias><name>outbound_ports</name><type>port</type><address>20000</address></alias>
            <alias><name>translated_ports</name><type>port</type><address>30000</address></alias>
            <alias><name>route_network</name><type>network</type><address>198.51.100.0/24</address></alias>
            <alias><name>vpn_network</name><type>network</type><address>203.0.113.0/24</address></alias>
            <alias><name>old_feed</name><type>urltable</type><url>https://example.com/feed</url><updatefreq>1</updatefreq></alias>
            <alias><name>old_urls</name><type>url</type><address>192.0.2.3</address><aliasurl>https://example.com/old</aliasurl></alias>
          </aliases>
          <filter><rule><disabled/><destination><address>used</address></destination><descr>idle</descr></rule>
            <rule><source><address>idle_child.example.com</address></source></rule></filter>
          <nat>
            <rule><destination><port>1000-forward_ports</port></destination></rule>
            <outbound><rule><sourceport>outbound_ports:21000</sourceport><natport>translated_ports</natport></rule></outbound>
          </nat>
          <staticroutes><route><network>route_network</network></route></staticroutes>
          <openvpn><openvpn-client><remote_network>192.0.2.0/24, vpn_network</remote_network></openvpn-client></openvpn>
        </pfsense>"""
        with open(self.tmp_file, "w") as config_file:
            config_file.write(config)

        aliases = [
            dict(name="idle", type="network", address="idle_child", descr="Old group", unused=True),
            dict(name="used", type="network", address="used_child", unused=False),
            dict(name="used_child", type="network", address="used used_leaf", unused=False),
            dict(name="used_leaf", type="host", address="192.0.2.1", unused=False),
            dict(name="idle_child", type="host", address="idle 192.0.2.2", detail="||old entry", unused=True),
            dict(name="forward_ports", type="port", address="8080", unused=False),
            dict(name="outbound_ports", type="port", address="20000", unused=False),
            dict(name="translated_ports", type="port", address="30000", unused=False),
            dict(name="route_network", type="network", address="198.51.100.0/24", unused=False),
            dict(name="vpn_network", type="network", address="203.0.113.0/24", unused=False),
            dict(name="old_feed", type="urltable", address="", url="https://example.com/feed", updatefreq="1", unused=True),
            dict(name="old_urls", type="url", address="192.0.2.3", aliasurl=["https://example.com/old"], unused=True),
        ]
        unused_aliases = [alias for alias in aliases if alias["unused"]]
        for params, expected in (({}, aliases), ({"only_unused": False}, aliases), ({"only_unused": True, "_ansible_check_mode": True}, unused_aliases)):
            with self.subTest(params=params), set_module_args(params):
                result = self.changed(False)
                self.assertEqual(result["aliases"], expected)
                for alias in result["aliases"]:
                    self.assertIs(type(alias["unused"]), bool)

        with open(self.tmp_file) as config_file:
            self.assertEqual(config_file.read(), config)
        self.php.assert_not_called()
        self.phpshell.assert_not_called()

    def test_reports_an_empty_list_without_aliases(self):
        with set_module_args({}):
            result = self.changed(False)

        self.assertEqual(result["aliases"], [])
