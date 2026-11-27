# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import patch
from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_openvpn_client
from .pfsense_module import TestPFSenseModule


class TestPFSenseOpenVPNClientModule(TestPFSenseModule):
    module = pfsense_openvpn_client

    def __init__(self, *args, **kwargs):
        super(TestPFSenseOpenVPNClientModule, self).__init__(*args, **kwargs)
        self.config_file = "pfsense_openvpn_config.xml"
        self.pfmodule = pfsense_openvpn_client.PFSenseOpenVPNClientModule

    def setUp(self):
        super(TestPFSenseOpenVPNClientModule, self).setUp()
        mock_php = patch("ansible_collections.pfsensible.core.plugins.module_utils.pfsense.PFSenseModule.php")
        self.php = mock_php.start()
        self.php.return_value = {"SHA256": "SHA256 (256-bit)"}
        self.addCleanup(mock_php.stop)

    def test_present_requires_server_address(self):
        with set_module_args(dict(name="c1", ca="OpenVPN CA")):
            self.execute_module(failed=True, msg="state is present but all of the following are missing: server_addr")

    def test_present_requires_mode_credential(self):
        for mode, credential in (("p2p_tls", "ca"), ("p2p_shared_key", "shared_key")):
            with self.subTest(mode=mode), set_module_args(dict(name="c1", mode=mode, server_addr="203.0.113.1")):
                self.execute_module(failed=True, msg="{0} is required for mode={1}".format(credential, mode))

    def test_openvpn_client_vip(self):
        """a client bound to a VIP stores its interface and address apart, as the web GUI does"""
        obj = dict(name="c1", ca="OpenVPN CA", server_addr="203.0.113.1", interface="Backup WAN IP", data_ciphers=["AES-256-GCM"])
        with set_module_args(obj):
            result = self.execute_module(changed=True)
            self.assertEqual(result["diff"]["after"]["interface"], "_viptestcarp")
            self.assertEqual(result["diff"]["after"]["ipaddr"], "192.0.2.10")
            self.changed(False)
        obj["interface"] = "wan"
        with set_module_args(obj):
            result = self.changed(True)
            self.assertEqual(result["diff"]["after"]["interface"], "wan")
            self.assertEqual(result["diff"]["after"]["ipaddr"], "")
            self.changed(False)
