# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import xml.etree.ElementTree as ET

from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import patch
from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_softflowd
from .pfsense_module import TestPFSenseModule


COLLECTOR = {"interface": ["Office", "lan", "lo0"], "host": "2001:db8::10", "port": "2055"}
CONFIG_PATH = "installedpackages/softflowd/config"


class TestPFSenseSoftflowdModule(TestPFSenseModule):
    module = pfsense_softflowd

    def setUp(self):
        super(TestPFSenseSoftflowdModule, self).setUp()
        self.config_file = "pfsense_softflowd_config.xml"
        self.load_fixtures()

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def assert_invalid(self, message, **params):
        with open(self.tmp_file, "rb") as config:
            before = config.read()
        with set_module_args(params):
            self.assertIn(message, self.failed()["msg"])
        with open(self.tmp_file, "rb") as config:
            self.assertEqual(config.read(), before)
        self.phpshell.assert_not_called()

    def softflowd_config(self):
        return ET.parse(self.tmp_file).find(CONFIG_PATH)

    def test_create_and_repeat(self):
        def apply_after_config_write(command):
            self.assertIn('require_once("/usr/local/pkg/softflowd.inc");', command)
            self.assertIn("sync_package_softflowd();", command)
            self.assertEqual(self.softflowd_config().findtext("interface"), "opt1,lan,lo0")
            return (0, "", "")

        self.phpshell.side_effect = apply_after_config_write
        result = self.run_module(changed=True, **COLLECTOR)
        self.assertEqual(
            {field.tag: field.text or "" for field in self.softflowd_config()},
            {
                "enable": "enabled",
                "interface": "opt1,lan,lo0",
                "host": "2001:db8::10",
                "port": "2055",
                "sample": "0",
                "maxflows": "",
                "hoplimit": "",
                "version": "10",
                "biflows": "",
                "flowtracking": "ether",
                "flowtimestamp": "sec",
                "timeout-general": "",
                "timeout-maxlife": "",
                "timeout-expint": "",
                "timeout-tcp": "",
                "timeout-tcp-rst": "",
                "timeout-tcp-fin": "",
                "timeout-udp": "",
            },
        )
        self.assertEqual(result["diff"]["after"]["host"], COLLECTOR["host"])
        self.phpshell.assert_called_once()
        self.phpshell.reset_mock()
        self.assertEqual(self.run_module(**COLLECTOR)["commands"], [])
        self.phpshell.assert_not_called()

    def test_partial_update_and_disable(self):
        self.run_module(changed=True, biflows=True, **COLLECTOR)
        self.assertEqual(self.softflowd_config().findtext("biflows"), "ON")
        self.phpshell.reset_mock()

        timeouts = dict(timeout_general=60, timeout_maxlife=0, timeout_expint=5, timeout_tcp=30, timeout_tcp_rst=6, timeout_tcp_fin=7, timeout_udp=45)
        result = self.run_module(changed=True, **timeouts)
        self.assertIn("timeout_udp='45'", result["commands"][0])
        config = self.softflowd_config()
        for field, value in timeouts.items():
            xml_field = field.replace("_", "-")
            self.assertEqual(config.findtext(xml_field), str(value))
            self.assertIsNone(config.find(field))
        self.assertEqual(config.findtext("host"), COLLECTOR["host"])
        self.assertEqual(config.findtext("biflows"), "ON")

        self.phpshell.reset_mock()
        self.run_module(changed=True, enable="off", version="9", biflows=False)
        config = self.softflowd_config()
        self.assertEqual(config.findtext("enable"), "off")
        self.assertEqual(config.findtext("version"), "9")
        self.assertEqual(config.findtext("biflows"), "")
        self.assertEqual(config.findtext("interface"), "opt1,lan,lo0")
        self.phpshell.assert_called_once()
        self.phpshell.reset_mock()
        self.run_module(enable="off", version="9", biflows=False)
        self.phpshell.assert_not_called()
        self.run_module(changed=True, enable="enabled")

    def test_create_disabled_and_validate_enabling(self):
        self.run_module(changed=True, enable="off")
        self.phpshell.reset_mock()
        self.run_module(enable="off")
        self.assert_invalid("Enabled softflowd requires: interface, host, port", enable="enabled")

    def test_validate_effective_version_and_biflows(self):
        self.run_module(changed=True, biflows=True, **COLLECTOR)
        self.phpshell.reset_mock()
        self.assert_invalid("biflows requires version 10 (IPFIX)", version="9")
        self.run_module(changed=True, version="9", biflows=False)
        self.phpshell.reset_mock()
        self.assert_invalid("biflows requires version 10 (IPFIX)", biflows=True)

    def test_invalid_options(self):
        cases = [
            ("Enabled softflowd requires: interface", {"interface": []}),
            ("does-not-exist is not a valid interface", {"interface": ["does-not-exist"]}),
            ("Inside must be an assigned interface or lo0", {"interface": ["Inside"]}),
            ("Duplicate softflowd interface: opt1", {"interface": ["Office", "opt1"]}),
            ("host must be an IPv4 or IPv6 address", {"host": "collector.example.com"}),
            ("host must be an IPv4 or IPv6 address", {"host": "fe80::1%invalid,192.0.2.4"}),
            ("port must be a UDP service name or a port number between 1 and 65535", {"port": "65536"}),
            ("port must be a UDP service name or a port number between 1 and 65535", {"port": "0"}),
            ("hoplimit must be between 1 and 255", {"hoplimit": 0}),
            ("hoplimit must be between 1 and 255", {"hoplimit": 256}),
            ("sample must be between 0 and 2147483647", {"sample": -1}),
            ("maxflows must be between 0 and 2147483647", {"maxflows": 2147483648}),
            ("timeout_general must be between 1 and 2147483647", {"timeout_general": 0}),
            ("timeout_udp must be between 0 and 2147483647", {"timeout_udp": -1}),
        ]
        for message, params in cases:
            with self.subTest(params=params):
                self.assert_invalid(message, **{**COLLECTOR, **params})

    def test_udp_service_name(self):
        with patch.object(pfsense_softflowd, "getservbyname", return_value=2055) as lookup:
            self.run_module(changed=True, **{**COLLECTOR, "host": "192.0.2.10", "port": "netflow"})
        lookup.assert_called_once_with("netflow", "udp")
        self.assertEqual(self.softflowd_config().findtext("port"), "netflow")
        self.run_module(changed=True, sample=100)

    def test_check_mode(self):
        result = self.run_module(changed=True, _ansible_check_mode=True, **COLLECTOR)
        self.assertEqual(result["diff"]["after"]["interface"], "opt1,lan,lo0")
        self.assertIsNone(self.softflowd_config())
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()

    def test_package_missing(self):
        config = ET.parse(self.tmp_file)
        config.getroot().remove(config.find("installedpackages"))
        config.write(self.tmp_file)
        self.assert_invalid("Unable to find package softflowd in installed packages", **COLLECTOR)
