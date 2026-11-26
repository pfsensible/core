# Copyright: (c) 2026, Romain Tiennot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import xml.etree.ElementTree as ET

from parameterized import parameterized

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_ipsec_settings
from .pfsense_module import TestPFSenseModule


PSK = "tunnel-test-psk"
TUNNEL = ("<client></client><phase1><ikeid>1</ikeid><descr>tunnel</descr><authentication_method>pre_shared_key</authentication_method>"
          "<pre-shared-key>{0}</pre-shared-key></phase1><phase2><ikeid>1</ikeid><mode>tunnel</mode></phase2>".format(PSK))

# The levels pfSense uses when none is stored (ipsec_get_loglevels() of /etc/inc/ipsec.inc)
DEFAULT_LEVELS = dict(dmn=1, mgr=1, ike=2, chd=2, job=1, cfg=2, knl=1, net=1, asn=1, enc=1, imc=1, imv=1, pts=1, tls=1, esp=1, lib=1)
STORED_LEVELS = dict((cat, str(level)) for cat, level in DEFAULT_LEVELS.items())
LEVELS_COMMAND = ", ".join("logging.{0}='{1}'".format(cat, level) for cat, level in DEFAULT_LEVELS.items())

# What a save of the page with its defaults and Auto-exclude LAN address unchecked leaves
SAVED = ("<logging>{0}</logging><async_crypto>enabled</async_crypto><uniqueids>replace</uniqueids>"
         "<noshuntlaninterfaces></noshuntlaninterfaces><filtermode>enc</filtermode><bypassrules></bypassrules>").format(
    "".join("<{0}>{1}</{0}>".format(cat, level) for cat, level in DEFAULT_LEVELS.items()))
STORED_SAVED = dict(logging=STORED_LEVELS, async_crypto="enabled", uniqueids="replace", noshuntlaninterfaces="", filtermode="enc", bypassrules=[])

RULES = [dict(source="192.168.1.0/24", destination="192.168.2.0/24"), dict(source="fd00:1::/64", destination="fd00:2::/64")]
STORED_RULES = [dict(source="192.168.1.0", srcmask="24", destination="192.168.2.0", dstmask="24"),
                dict(source="fd00:1::", srcmask="64", destination="fd00:2::", dstmask="64")]


class TestPFSenseIpsecSettingsModule(TestPFSenseModule):
    module = pfsense_ipsec_settings

    def setUp(self):
        super(TestPFSenseIpsecSettingsModule, self).setUp()
        self.write_config()

    def write_config(self, settings="", tunnel=TUNNEL):
        with open(self.tmp_file, "w") as config:
            config.write("<pfsense><version>24.0</version><ipsec>{0}{1}</ipsec></pfsense>".format(tunnel, settings))

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def stored(self):
        """ the settings stored in <ipsec>, without the tunnels """
        values = dict()
        for elt in ET.parse(self.tmp_file).find("ipsec"):
            if elt.tag in ["client", "phase1", "phase2"]:
                continue
            if elt.tag == "logging":
                values[elt.tag] = dict((child.tag, child.text) for child in elt)
            elif elt.tag == "bypassrules":
                values[elt.tag] = [dict((child.tag, child.text) for child in rule) for rule in elt]
            else:
                values[elt.tag] = elt.text or ""
        return values

    def php_command(self):
        return self.phpshell.call_args[0][0]

    def test_async_crypto_and_default_levels(self):
        params = dict(async_crypto=True, logging=DEFAULT_LEVELS)
        result = self.run_module(changed=True, _ansible_diff=True, **params)
        self.assertEqual(self.stored(), dict(logging=STORED_LEVELS, async_crypto="enabled"))
        self.assertEqual(result["commands"], ["update ipsec_settings ipsec set {0}, async_crypto=True".format(LEVELS_COMMAND)])
        self.assertIn("ipsec_configure(false, false);", self.php_command())
        self.assertIn("system_setup_sysctl();", self.php_command())
        # The tunnels are kept, and neither they nor their keys are in the output
        self.assertEqual(ET.parse(self.tmp_file).findtext("ipsec/phase1/pre-shared-key"), PSK)
        self.assertNotIn("phase1", result["diff"]["before"])
        self.assertNotIn(PSK, repr(result))
        self.assertEqual(self.run_module(**params)["commands"], [])

    def test_saved_page_is_unchanged(self):
        self.write_config(SAVED)
        self.run_module(async_crypto=True, logging=DEFAULT_LEVELS, uniqueids="replace", filtermode="enc", noshuntlaninterfaces=True,
                        ipsecbypass=False)
        self.assertEqual(self.stored(), STORED_SAVED)
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()

    def test_one_level(self):
        self.write_config(SAVED)
        result = self.run_module(changed=True, logging=dict(ike=4))
        self.assertEqual(result["commands"], ["update ipsec_settings ipsec set logging.ike='4'"])
        self.assertEqual(self.stored(), dict(STORED_SAVED, logging=dict(STORED_LEVELS, ike="4")))

    def test_level_kept_in_page_order(self):
        self.write_config("<logging><ike>2</ike></logging>")
        self.run_module(changed=True, logging=dict(lib=-1, dmn=0))
        self.assertEqual(list(self.stored()["logging"].items()), [("ike", "2"), ("dmn", "0"), ("lib", "-1")])

    def test_async_crypto_off(self):
        self.run_module(async_crypto=False)
        self.assertEqual(self.stored(), dict())
        self.write_config(SAVED)
        result = self.run_module(changed=True, async_crypto=False)
        self.assertEqual(result["commands"], ["update ipsec_settings ipsec set async_crypto=False"])
        self.assertEqual(self.stored()["async_crypto"], "disabled")

    def test_check_boxes(self):
        params = dict(noshuntlaninterfaces=True, makebeforebreak=True, strictcrlpolicy=True)
        result = self.run_module(changed=True, **params)
        self.assertEqual(result["commands"], ["update ipsec_settings ipsec set strictcrlpolicy=True, makebeforebreak=True, noshuntlaninterfaces=True"])
        self.assertEqual(self.stored(), dict(strictcrlpolicy="", makebeforebreak="", noshuntlaninterfaces=""))
        self.assertIn("ipsec_configure(false, false);", self.php_command())
        self.run_module(**params)
        self.run_module(changed=True, noshuntlaninterfaces=False, makebeforebreak=False, strictcrlpolicy=False)
        self.assertEqual(self.stored(), dict())

    def test_restart(self):
        result = self.run_module(changed=True, unityplugin=True)
        self.assertEqual(result["commands"], ["update ipsec_settings ipsec set unityplugin=True"])
        self.assertIn("ipsec_configure(true, false);", self.php_command())

    def test_dns_interval(self):
        result = self.run_module(changed=True, dns_interval=120)
        self.assertEqual(result["commands"], ["update ipsec_settings ipsec set dns_interval='120'"])
        self.assertEqual(self.stored(), {"dns-interval": "120"})
        self.assertIn("ipsec_configure(false, true);", self.php_command())

    def test_uniqueids_and_filtermode(self):
        self.write_config(SAVED)
        result = self.run_module(changed=True, uniqueids="never", filtermode="if_ipsec")
        self.assertEqual(result["commands"], ["update ipsec_settings ipsec set uniqueids='never', filtermode='if_ipsec'"])
        self.assertEqual(self.stored(), dict(STORED_SAVED, uniqueids="never", filtermode="if_ipsec"))

    def test_numbers(self):
        params = dict(port=1500, port_nat_t=4501, maxexchange=10, ikev2_retransmit_timeout=4.0, ikev2_retransmit_base=1.5)
        self.run_module(changed=True, **params)
        self.assertEqual(self.stored(), dict(maxexchange="10", port="1500", port_nat_t="4501", ikev2_retransmit_timeout="4",
                                             ikev2_retransmit_base="1.5"))
        self.run_module(**params)
        result = self.run_module(changed=True, port=0, maxexchange=0)
        self.assertEqual(result["commands"], ["update ipsec_settings ipsec set maxexchange=none, port=none"])
        self.assertIn("ipsec_configure(true, false);", self.php_command())
        self.assertNotIn("port", self.stored())

    def test_number_stored_as_typed(self):
        self.write_config("<ikev2_retransmit_timeout>4.0</ikev2_retransmit_timeout><ikev2_retransmit_tries>05</ikev2_retransmit_tries>")
        self.run_module(ikev2_retransmit_timeout=4, ikev2_retransmit_tries=5)

    def test_bypass_rules(self):
        result = self.run_module(changed=True, ipsecbypass=True, bypassrules=RULES)
        self.assertEqual(result["commands"], ["update ipsec_settings ipsec set ipsecbypass=True, bypassrules='192.168.1.0/24 to 192.168.2.0/24, "
                                              "fd00:1::/64 to fd00:2::/64'"])
        self.assertEqual(self.stored(), dict(ipsecbypass="", bypassrules=STORED_RULES))
        self.run_module(ipsecbypass=True, bypassrules=RULES)
        self.run_module(changed=True, bypassrules=RULES[1:])
        self.assertEqual(self.stored(), dict(ipsecbypass="", bypassrules=STORED_RULES[1:]))

    def test_bypass_off_removes_rules(self):
        self.write_config("<ipsecbypass></ipsecbypass><bypassrules><rule><source>192.168.1.0</source><srcmask>24</srcmask>"
                          "<destination>192.168.2.0</destination><dstmask>24</dstmask></rule></bypassrules>")
        result = self.run_module(changed=True, ipsecbypass=False)
        self.assertEqual(result["commands"], ["update ipsec_settings ipsec set ipsecbypass=False, bypassrules=none"])
        self.assertEqual(self.stored(), dict(bypassrules=[]))
        self.run_module(ipsecbypass=False)

    def test_pkcs11_off_when_unused(self):
        self.write_config("<pkcs11support></pkcs11support>", tunnel=TUNNEL.replace("<descr>", "<disabled></disabled><descr>").replace(
            "pre_shared_key<", "pkcs11<"))
        self.run_module(changed=True, pkcs11support=False)
        self.assertEqual(self.stored(), dict())
        self.assertIn("ipsec_configure(true, false);", self.php_command())

    def test_check_mode(self):
        self.run_module(changed=True, _ansible_check_mode=True, async_crypto=True, logging=DEFAULT_LEVELS)
        self.assertEqual(self.stored(), dict())
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()

    def test_untouched_configuration(self):
        self.run_module()
        self.run_module(logging=dict())
        self.write_config(SAVED)
        self.run_module()
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()

    def test_new_ipsec_section(self):
        with open(self.tmp_file, "w") as config:
            config.write("<pfsense><version>24.0</version></pfsense>")
        self.run_module(changed=True, async_crypto=True)
        self.assertEqual(self.stored(), dict(async_crypto="enabled"))

    @parameterized.expand([
        ("maxexchange must be between 3 and 64", dict(maxexchange=2)),
        ("maxexchange must be between 3 and 64", dict(maxexchange=65)),
        ("port must be between 1 and 65535", dict(port=65536)),
        ("port_nat_t must be between 1 and 65535", dict(port_nat_t=70000)),
        ("dns_interval must be 0 or more", dict(dns_interval=-1)),
        ("ikev2_retransmit_tries must be 0 or more", dict(ikev2_retransmit_tries=-1)),
        ("ikev2_retransmit_base must be 0 or more", dict(ikev2_retransmit_base=-1.8)),
        ("port and port_nat_t must be different", dict(port=4500, port_nat_t=4500)),
        ("192.168.1.0 is not a valid source network", dict(ipsecbypass=True, bypassrules=[dict(source="192.168.1.0", destination="10.0.0.0/8")])),
        ("10.0.0.0/33 is not a valid destination", dict(ipsecbypass=True, bypassrules=[dict(source="192.168.1.0/24", destination="10.0.0.0/33")])),
        ("fw1/24 is not a valid source", dict(ipsecbypass=True, bypassrules=[dict(source="fw1/24", destination="10.0.0.0/8")])),
        ("same address family", dict(ipsecbypass=True, bypassrules=[dict(source="192.168.1.0/24", destination="fd00::/64")])),
        ("bypassrules requires ipsecbypass", dict(bypassrules=[dict(source="192.168.1.0/24", destination="10.0.0.0/8")])),
        ("bypassrules requires ipsecbypass", dict(ipsecbypass=False, bypassrules=RULES)),
        ("bypassrules is required with ipsecbypass", dict(ipsecbypass=True)),
        ("bypassrules is required with ipsecbypass", dict(ipsecbypass=True, bypassrules=[])),
        ("value of ike must be one of", dict(logging=dict(ike=5))),
    ])
    def test_invalid_option(self, msg, params):
        with set_module_args(params):
            self.assertIn(msg, self.failed()["msg"])
        self.assertFalse(os.path.exists(self.backup_file))

    def test_port_same_as_stored_nat_t(self):
        self.write_config("<port_nat_t>4500</port_nat_t>")
        with set_module_args(dict(port=4500)):
            self.assertIn("port and port_nat_t must be different", self.failed()["msg"])

    def test_pkcs11_in_use(self):
        self.write_config("<pkcs11support></pkcs11support>", tunnel=TUNNEL.replace("pre_shared_key<", "pkcs11<"))
        with set_module_args(dict(pkcs11support=False)):
            self.assertIn("Unable to disable PKCS#11 support", self.failed()["msg"])
        self.assertFalse(os.path.exists(self.backup_file))
