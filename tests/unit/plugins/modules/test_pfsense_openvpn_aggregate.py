# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import xml.etree.ElementTree as ET

from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import patch
from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_openvpn_aggregate
from .pfsense_module import TestPFSenseModule
from .test_pfsense_openvpn_server import TLSKEY

# ovpns2 and delvpnuser as the fixture has them
SERVER2 = dict(name="ovpns2", mode="p2p_tls", ca="OpenVPN CA", local_port=1195, tls=TLSKEY, tls_type="auth")
OVERRIDE = dict(name="delvpnuser", gwredir=True, server_list=["1"], custom_options="ifconfig-push 10.8.0.1 255.255.255.0")
CLIENT = "<openvpn-client><vpnid>3</vpnid><description>ovpnc3</description><mode>p2p_tls</mode></openvpn-client>"
SERVER2_COPY = "<openvpn-server><vpnid>5</vpnid><description>ovpns2</description><mode>p2p_tls</mode></openvpn-server>"


class TestPFSenseOpenVPNAggregateModule(TestPFSenseModule):
    module = pfsense_openvpn_aggregate

    def __init__(self, *args, **kwargs):
        super(TestPFSenseOpenVPNAggregateModule, self).__init__(*args, **kwargs)
        self.config_file = "pfsense_openvpn_config.xml"
        self.extra = [CLIENT]
        self.calls = []

    def setUp(self):
        super(TestPFSenseOpenVPNAggregateModule, self).setUp()
        mock_run_command = patch("ansible.module_utils.basic.AnsibleModule.run_command")
        mock_run_command.start().return_value = (0, base64.b64decode(TLSKEY.encode()).decode(), "")
        self.addCleanup(mock_run_command.stop)
        mock_php = patch("ansible_collections.pfsensible.core.plugins.module_utils.pfsense.PFSenseModule.php")
        mock_php.start().return_value = {"SHA256": "SHA256 (256-bit)"}
        self.addCleanup(mock_php.stop)
        self.phpshell.side_effect = self.record_phpshell

    def load_fixtures(self):
        """the fixture with a client, and the extra entries of the test"""
        super(TestPFSenseOpenVPNAggregateModule, self).load_fixtures()
        tree = ET.parse(self.tmp_file)
        for extra in self.extra:
            tree.getroot().find("openvpn").append(ET.fromstring(extra))
        tree.write(self.tmp_file)

    def record_phpshell(self, command):
        """keep each PHP command with config.xml as it was when it ran"""
        self.calls.append((command, ET.parse(self.tmp_file).getroot()))
        return (0, "", "")

    def run_aggregate(self, changed=True, **params):
        with set_module_args(params):
            return self.execute_module(changed=changed)

    def names(self, tag, field="description", root=None):
        if root is None:
            root = ET.parse(self.tmp_file).getroot()
        return [elt.findtext(field) for elt in root.find("openvpn").findall(tag)]

    def php_command(self):
        """the one PHP command run, once config.xml was written"""
        self.assertEqual(len(self.calls), 1, self.calls)
        return self.calls[0]

    def test_noop(self):
        self.run_aggregate(changed=False, aggregated_openvpn_servers=[SERVER2], aggregated_openvpn_overrides=[OVERRIDE])
        self.assertEqual(self.calls, [])

    def test_purge_servers_check_mode(self):
        result = self.run_aggregate(aggregated_openvpn_servers=[SERVER2], purge_openvpn_servers=True, _ansible_check_mode=True)
        self.assertEqual(result["result_openvpn_servers"], ["delete openvpn_server 'ovpns1'"])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.names("openvpn-server"), ["ovpns1", "ovpns2"])

    def test_purge_servers(self):
        result = self.run_aggregate(aggregated_openvpn_servers=[SERVER2], purge_openvpn_servers=True)
        self.assertEqual(result["result_openvpn_servers"], ["delete openvpn_server 'ovpns1'"])
        (command, config) = self.php_command()
        self.assertIn("openvpn_delete('server', array('vpnid' => '1'));", command)
        self.assertNotIn("openvpn_resync", command)
        self.assertEqual(self.names("openvpn-server", root=config), ["ovpns2"])

    def test_purge_copies(self):
        self.extra = [CLIENT, SERVER2_COPY]
        result = self.run_aggregate(aggregated_openvpn_servers=[SERVER2], purge_openvpn_servers=True)
        self.assertEqual(result["result_openvpn_servers"], ["delete openvpn_server 'ovpns1'", "delete openvpn_server 'ovpns2'"])
        (command, config) = self.php_command()
        self.assertIn("openvpn_delete('server', array('vpnid' => '1'));\nopenvpn_delete('server', array('vpnid' => '5'));\n", command)
        self.assertEqual([elt.findtext("vpnid") for elt in config.find("openvpn").findall("openvpn-server")], ["2"])

    def test_purge_clients(self):
        result = self.run_aggregate(aggregated_openvpn_clients=[], purge_openvpn_clients=True)
        # pfsense_openvpn_client logs its commands as "openvpn"
        self.assertEqual(result["result_openvpn_clients"], ["delete openvpn 'ovpnc3'"])
        (command, config) = self.php_command()
        self.assertIn("openvpn_delete('client', array('vpnid' => '3'));", command)
        self.assertEqual(self.names("openvpn-client", root=config), [])

    def test_absent_client(self):
        self.run_aggregate(aggregated_openvpn_clients=[dict(name="ovpnc3", state="absent")])
        (command, config) = self.php_command()
        self.assertIn("openvpn_delete('client', array('vpnid' => '3'));", command)
        self.assertEqual(self.names("openvpn-client", root=config), [])

    def test_update_server(self):
        result = self.run_aggregate(aggregated_openvpn_servers=[dict(SERVER2, tunnel_network="10.10.10.10/24")])
        self.assertEqual(result["result_openvpn_servers"], ["update openvpn_server 'ovpns2' set "])
        (command, config) = self.php_command()
        self.assertIn("if (in_array($ovpn['vpnid'], array('2'), true)) { openvpn_resync('server', $ovpn); }", command)
        self.assertIn("openvpn_resync_csc_all();", command)
        self.assertNotIn("openvpn_delete", command)

    def test_overrides(self):
        result = self.run_aggregate(aggregated_openvpn_overrides=[dict(name="vpnuser1", block=True)], purge_openvpn_overrides=True)
        self.assertEqual(
            result["result_openvpn_overrides"], ["create openvpn_override 'vpnuser1', common_name='vpnuser1'", "delete openvpn_override 'delvpnuser'"]
        )
        (command, config) = self.php_command()
        self.assertIn("openvpn_delete_csc(array('common_name' => 'delvpnuser', 'server_list' => '1'));", command)
        self.assertIn("if (in_array($csc['common_name'], array('vpnuser1'), true)) { openvpn_resync_csc($csc); }", command)
        self.assertNotIn("openvpn_resync(", command)
        self.assertEqual(self.names("openvpn-csc", "common_name", root=config), ["vpnuser1"])

    def test_absent_item(self):
        result = self.run_aggregate(aggregated_openvpn_overrides=[dict(name="delvpnuser", state="absent")])
        self.assertEqual(result["result_openvpn_overrides"], ["delete openvpn_override 'delvpnuser'"])
        (command, config) = self.php_command()
        self.assertIn("openvpn_delete_csc(array('common_name' => 'delvpnuser', 'server_list' => '1'));", command)
