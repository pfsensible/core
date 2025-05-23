# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from pathlib import Path
import xml.etree.ElementTree as ET

from parameterized import parameterized

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_rfc2136
from .pfsense_module import TestPFSenseModule


ENTRY = dict(descr="Office's DNS", host="office.example.com.", ttl=60, keyname="office-update.example.com.", keydata="dGVzdC1vbGQta2V5")
NEW_KEY = "dGVzdC1uZXcta2V5"
FORCED_UPDATE = """require_once("services.inc"); services_dnsupdate_process("", "office.example.com", true);"""


class TestPFSenseRfc2136Module(TestPFSenseModule):
    module = pfsense_rfc2136

    def setUp(self):
        super(TestPFSenseRfc2136Module, self).setUp()
        self.config = Path(self.tmp_file)
        self.config.write_text(
            "<pfsense><version>24.0</version>"
            "<interfaces><wan><descr>WAN</descr></wan><lan><descr>OFFICE</descr></lan></interfaces>"
            "<gateways><gateway_group><name>Failover</name></gateway_group></gateways></pfsense>"
        )

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def entry(self):
        return ET.parse(self.config).find("dnsupdates/dnsupdate")

    def test_create_defaults_and_repeat(self):
        result = self.run_module(changed=True, **ENTRY)
        entry = self.entry()
        self.assertEqual(entry.findtext("host"), "office.example.com")
        self.assertEqual(entry.findtext("keyname"), ENTRY["keyname"])
        self.assertEqual(entry.findtext("keydata"), ENTRY["keydata"])
        self.assertEqual(entry.findtext("ttl"), "60")
        self.assertEqual(entry.findtext("interface"), "wan")
        self.assertEqual(entry.findtext("keyalgorithm"), "hmac-md5")
        self.assertEqual(entry.findtext("recordtype"), "both")
        for option in ("zone", "server", "updatesource", "updatesourcefamily"):
            self.assertEqual(entry.findtext(option), "")
        for option in ("enable", "usetcp", "usepublicip"):
            self.assertIsNone(entry.find(option))
        self.assertTrue(result["commands"][0].startswith("create rfc2136 "))
        self.assertNotIn(ENTRY["keydata"], repr(result))
        after_create = self.config.read_bytes()
        self.run_module(**ENTRY)
        self.assertEqual(self.config.read_bytes(), after_create)
        self.phpshell.assert_not_called()

    def test_apply_uses_forced_host_update_only_on_enabled_changes(self):
        self.run_module(changed=True, **ENTRY, interface="Failover", enable=True, updatesource="OFFICE", usetcp=True, usepublicip=True)
        self.phpshell.assert_called_once_with(FORCED_UPDATE, debug=False)
        self.assertEqual(self.entry().findtext("updatesource"), "lan")

        updated_entry = ENTRY.copy()
        updated_entry.update(ttl=300, keydata=NEW_KEY)
        self.phpshell.reset_mock()
        result = self.run_module(changed=True, **updated_entry)
        for key in (ENTRY["keydata"], NEW_KEY):
            self.assertNotIn(key, repr(result))
        self.phpshell.assert_called_once_with(FORCED_UPDATE, debug=False)
        entry = self.entry()
        self.assertEqual(entry.findtext("interface"), "Failover")
        self.assertEqual(entry.findtext("updatesource"), "lan")
        self.assertEqual(entry.findtext("ttl"), "300")
        self.assertEqual(entry.findtext("keydata"), NEW_KEY)
        for field in ("enable", "usetcp", "usepublicip"):
            self.assertEqual(entry.findtext(field), "")

        self.phpshell.reset_mock()
        self.run_module(changed=True, **updated_entry, enable=False, usetcp=False, usepublicip=False)
        for field in ("enable", "usetcp", "usepublicip"):
            self.assertIsNone(self.entry().find(field))
        self.run_module(**updated_entry, enable=False, usetcp=False, usepublicip=False)
        self.phpshell.assert_not_called()

    def test_check_mode_and_delete_by_description(self):
        before = self.config.read_bytes()
        self.run_module(changed=True, **ENTRY, enable=True, _ansible_check_mode=True)
        self.assertEqual(self.config.read_bytes(), before)
        self.phpshell.assert_not_called()

        self.run_module(changed=True, **ENTRY, enable=True)
        self.phpshell.reset_mock()
        after_create = self.config.read_bytes()
        absent = dict(descr=ENTRY["descr"], state="absent")
        result = self.run_module(changed=True, **absent, _ansible_check_mode=True)
        self.assertNotIn(ENTRY["keydata"], repr(result))
        self.assertEqual(self.config.read_bytes(), after_create)
        result = self.run_module(changed=True, **absent)
        self.assertNotIn(ENTRY["keydata"], repr(result))
        self.assertIsNone(self.entry())
        self.run_module(**absent)
        self.phpshell.assert_not_called()

    @parameterized.expand([("192.0.2.8 5353", "192.0.2.1"), ("2001:db8::8", "2001:db8::1"), ("ns.example.com.", "none")])
    def test_server_and_source_values(self, server, source):
        self.run_module(changed=True, **ENTRY, server=server, updatesource=source)
        self.assertEqual(self.entry().findtext("server"), server)
        self.assertEqual(self.entry().findtext("updatesource"), source)
        self.run_module(changed=True, **ENTRY, server="", updatesource="")
        self.assertEqual(self.entry().findtext("server"), "")
        self.assertEqual(self.entry().findtext("updatesource"), "")

    @parameterized.expand([("host",), ("ttl",), ("keyname",), ("keydata",)])
    def test_required_for_present(self, missing):
        params = {field: value for field, value in ENTRY.items() if field != missing}
        with set_module_args(params):
            self.assertIn(missing, self.failed()["msg"])

    @parameterized.expand(
        [
            ("descr", " "),
            ("host", ""),
            ("host", "office.example.com\n"),
            ("host", "office..example.com"),
            ("host", "a" * 64 + ".example.com"),
            ("zone", "-example.com"),
            ("ttl", -1),
            ("ttl", 2147483648),
            ("keyname", "invalid/key"),
            ("keydata", ""),
            ("keydata", "raw secret"),
            ("keydata", "dGVzdA==\n"),
            ("server", "192.0.2.999"),
            ("server", "ns.example.com 65536"),
            ("server", "ns.example.com\n"),
            ("interface", "bad-interface"),
            ("updatesource", "missing"),
            ("recordtype", "PTR"),
        ]
    )
    def test_invalid_option_does_not_write_or_apply(self, option, value):
        before = self.config.read_bytes()
        with set_module_args(dict(ENTRY, **{option: value})):
            self.failed()
        self.assertEqual(self.config.read_bytes(), before)
        self.phpshell.assert_not_called()

    def test_duplicate_description_fails(self):
        self.run_module(changed=True, **ENTRY)
        tree = ET.parse(self.config)
        parent = tree.find("dnsupdates")
        parent.append(parent[0])
        tree.write(self.config)
        with set_module_args(dict(descr=ENTRY["descr"], state="absent")):
            self.assertIn("multiple RFC 2136 entries", self.failed()["msg"])
        self.assertEqual(len(ET.parse(self.config).findall("dnsupdates/dnsupdate")), 2)
