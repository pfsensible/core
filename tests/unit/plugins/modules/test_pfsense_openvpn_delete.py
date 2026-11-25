# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Deleting an OpenVPN server, client or override: the PHP that stops it runs once config.xml is
# written, and never in check mode.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import xml.etree.ElementTree as ET

from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import patch
from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_openvpn_client, pfsense_openvpn_override, pfsense_openvpn_server
from .pfsense_module import TestPFSenseModule

CLIENT = "<openvpn-client><vpnid>3</vpnid><description>ovpnc3</description><mode>p2p_tls</mode></openvpn-client>"
# The client module asks for these even with state=absent
CLIENT_PARAMS = dict(server_addr="192.0.2.1", ca="OpenVPN CA")


class TestPFSenseOpenVPNDelete(TestPFSenseModule):

    def __init__(self, *args, **kwargs):
        super(TestPFSenseOpenVPNDelete, self).__init__(*args, **kwargs)
        self.config_file = "pfsense_openvpn_config.xml"
        self.calls = []

    def setUp(self):
        super(TestPFSenseOpenVPNDelete, self).setUp()
        mock_php = patch("ansible_collections.pfsensible.core.plugins.module_utils.pfsense.PFSenseModule.php")
        mock_php.start().return_value = {"SHA256": "SHA256 (256-bit)"}
        self.addCleanup(mock_php.stop)
        self.phpshell.side_effect = self.record_phpshell

    def load_fixtures(self):
        """ the fixture with a client added """
        super(TestPFSenseOpenVPNDelete, self).load_fixtures()
        tree = ET.parse(self.tmp_file)
        tree.getroot().find("openvpn").append(ET.fromstring(CLIENT))
        tree.write(self.tmp_file)

    def record_phpshell(self, command):
        """ keep each PHP command with config.xml as it was when it ran """
        self.calls.append((command, ET.parse(self.tmp_file).getroot()))
        return (0, "", "")

    def delete(self, module, name, check_mode=False, **params):
        self.module = module
        with set_module_args(dict(name=name, state="absent", _ansible_check_mode=check_mode, **params)):
            return self.execute_module(changed=True)

    def assert_deleted_then_run(self, php, tag, field, name):
        self.assertEqual(len(self.calls), 1, self.calls)
        (command, config) = self.calls[0]
        self.assertIn(php, command)
        self.assertEqual([elt for elt in config.find("openvpn").findall(tag) if elt.findtext(field) == name], [])

    def test_server(self):
        result = self.delete(pfsense_openvpn_server, "ovpns2")
        self.assertEqual(result["vpnid"], 2)
        self.assert_deleted_then_run("openvpn_delete('server', array('vpnid' => '2'));", "openvpn-server", "description", "ovpns2")

    def test_server_check_mode(self):
        self.delete(pfsense_openvpn_server, "ovpns2", check_mode=True)
        self.assertEqual(self.calls, [])

    def test_client(self):
        result = self.delete(pfsense_openvpn_client, "ovpnc3", **CLIENT_PARAMS)
        self.assertEqual(result["vpnid"], 3)
        self.assert_deleted_then_run("openvpn_delete('client', array('vpnid' => '3'));", "openvpn-client", "description", "ovpnc3")

    def test_client_check_mode(self):
        self.delete(pfsense_openvpn_client, "ovpnc3", check_mode=True, **CLIENT_PARAMS)
        self.assertEqual(self.calls, [])

    def test_override(self):
        self.delete(pfsense_openvpn_override, "delvpnuser")
        self.assert_deleted_then_run(
            "openvpn_delete_csc(array('common_name' => 'delvpnuser', 'server_list' => '1'));", "openvpn-csc", "common_name", "delvpnuser")

    def test_override_check_mode(self):
        self.delete(pfsense_openvpn_override, "delvpnuser", check_mode=True)
        self.assertEqual(self.calls, [])
