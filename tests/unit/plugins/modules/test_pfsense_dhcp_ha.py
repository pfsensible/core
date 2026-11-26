# Copyright: (c) 2026, Romain Tiennot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import xml.etree.ElementTree as ET

from parameterized import parameterized

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_dhcp_ha
from .pfsense_module import TestPFSenseModule


CERTS = ("<cert><refid>6a1b2c3d4e5f6</refid><descr>DHCP HA</descr><crt>Y3J0</crt><prv>cHJ2</prv></cert>"
         "<cert><refid>6a1b2c3d4e5f7</refid><descr>DHCP HA client</descr><crt>Y3J0</crt><prv>cHJ2</prv></cert>"
         "<cert><refid>6a1b2c3d4e5f8</refid><descr>No key</descr><crt>Y3J0</crt></cert>")

PRIMARY = dict(enable=True, role="primary", localip="192.168.4.1", remotename="fw2", remoteip="192.168.4.2")
STORED_PRIMARY = dict(enable="", role="primary", localip="192.168.4.1", remotename="fw2", remoteip="192.168.4.2")

# What the configuration sync of the primary leaves on the secondary
SYNCED = "<ha><enable></enable><role>standby</role><localip>192.168.4.2</localip><remoteip>192.168.4.1</remoteip><remotename>fw1</remotename></ha>"
SYNCED_TLS = ("<ha><enable></enable><role>primary</role><localip>192.168.4.1</localip><remoteip>192.168.4.2</remoteip><remotename>fw2</remotename>"
              "<tls></tls><scertref>6a1b2c3d4e5f6</scertref><mutualtls></mutualtls><ccertref>6a1b2c3d4e5f7</ccertref></ha>")


class TestPFSenseDHCPHAModule(TestPFSenseModule):
    module = pfsense_dhcp_ha

    def setUp(self):
        super(TestPFSenseDHCPHAModule, self).setUp()
        self.write_config()

    def write_config(self, kea="", kea6=""):
        with open(self.tmp_file, "w") as config:
            config.write("<pfsense><version>24.0</version><system><hostname>fw1</hostname></system>{0}"
                         "<kea>{1}</kea><kea6>{2}</kea6></pfsense>".format(CERTS, kea, kea6))

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def stored(self, root="kea"):
        ha = ET.parse(self.tmp_file).find(root + "/ha")
        return None if ha is None else {child.tag: child.text or "" for child in ha}

    def test_primary_and_repeat(self):
        params = dict(PRIMARY, tls=True, scert="DHCP HA")
        result = self.run_module(changed=True, **params)
        self.assertEqual(self.stored(), dict(STORED_PRIMARY, tls="", scertref="6a1b2c3d4e5f6"))
        self.assertEqual(result["commands"], ["update dhcp_ha kea set enable=True, role='primary', localip='192.168.4.1', remotename='fw2', "
                                              "remoteip='192.168.4.2', tls=True, scert='DHCP HA'"])
        self.assertIn('services_dhcpd_configure("inet");', self.phpshell.call_args[0][0])
        self.assertEqual(self.run_module(**params)["commands"], [])

    def test_secondary_certificate(self):
        self.write_config(kea=SYNCED)
        result = self.run_module(changed=True, tls=True, scert="DHCP HA")
        self.assertEqual(result["commands"], ["update dhcp_ha kea set tls=True, scert='DHCP HA'"])
        self.assertEqual(self.stored(), dict(enable="", role="standby", localip="192.168.4.2", remoteip="192.168.4.1", remotename="fw1",
                                             tls="", scertref="6a1b2c3d4e5f6"))

    def test_change_certificate(self):
        self.write_config(kea=SYNCED_TLS)
        result = self.run_module(changed=True, scert="DHCP HA client", _ansible_diff=True)
        self.assertEqual(result["commands"], ["update dhcp_ha kea set scert='DHCP HA client'"])
        self.assertEqual(result["diff"]["before"]["scertref"], "6a1b2c3d4e5f6")
        self.assertEqual(result["diff"]["after"]["scertref"], "6a1b2c3d4e5f7")

    def test_disable_removes_role(self):
        self.write_config(kea=SYNCED)
        result = self.run_module(changed=True, enable=False)
        self.assertEqual(result["commands"], ["update dhcp_ha kea set enable=False, role=none"])
        self.assertEqual(self.stored(), dict(localip="192.168.4.2", remoteip="192.168.4.1", remotename="fw1"))
        self.run_module(enable=False)

    def test_tls_off_removes_certificates(self):
        self.write_config(kea=SYNCED_TLS)
        result = self.run_module(changed=True, tls=False)
        self.assertEqual(result["commands"], ["update dhcp_ha kea set tls=False, scert=none, mutualtls=False, ccert=none"])
        self.assertEqual(self.stored(), STORED_PRIMARY)

    def test_mutualtls_off_removes_client_certificate(self):
        self.write_config(kea=SYNCED_TLS)
        self.run_module(changed=True, mutualtls=False)
        self.assertEqual(self.stored(), dict(STORED_PRIMARY, tls="", scertref="6a1b2c3d4e5f6"))

    def test_mutualtls(self):
        self.run_module(changed=True, mutualtls=True, ccert="DHCP HA client", tls=True, scert="DHCP HA", **PRIMARY)
        self.assertEqual(self.stored(), dict(STORED_PRIMARY, tls="", scertref="6a1b2c3d4e5f6", mutualtls="", ccertref="6a1b2c3d4e5f7"))

    def test_timers_and_ports(self):
        self.write_config(kea=SYNCED)
        result = self.run_module(changed=True, localport=8766, remoteport=8766, heartbeatdelay=5000, maxunackedclients=2)
        self.assertEqual(result["commands"], ["update dhcp_ha kea set localport='8766', remoteport='8766', heartbeatdelay='5000', "
                                              "maxunackedclients='2'"])
        self.assertEqual(self.stored()["heartbeatdelay"], "5000")

    def test_empty_localname_removes_it(self):
        self.write_config(kea=SYNCED.replace("<enable>", "<localname></localname><enable>"))
        self.run_module(changed=True, localname="")
        self.assertNotIn("localname", self.stored())
        self.run_module(localname="")

    def test_inet6(self):
        result = self.run_module(changed=True, ipprotocol="inet6", **PRIMARY)
        self.assertEqual(result["commands"][0].split(" set ")[0], "update dhcp_ha kea6")
        self.assertEqual(self.stored("kea6"), STORED_PRIMARY)
        self.assertIsNone(self.stored("kea"))
        self.assertIn('services_dhcpd_configure("inet6");', self.phpshell.call_args[0][0])

    def test_check_mode(self):
        self.run_module(changed=True, _ansible_check_mode=True, **PRIMARY)
        self.assertIsNone(self.stored())
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()

    def test_untouched_configuration(self):
        self.run_module()
        self.run_module(ipprotocol="inet6")
        self.write_config(kea=SYNCED)
        self.run_module(enable=True, role="standby")
        self.assertFalse(os.path.exists(self.backup_file))
        self.phpshell.assert_not_called()

    @parameterized.expand([
        ("localname must be hostname-like", dict(localname="fw 1")),
        ("remotename must be hostname-like", dict(remotename="-fw2")),
        ("localip must be a valid", dict(localip="192.168.4.300")),
        ("remoteip must be a valid", dict(remoteip="fw2")),
        ("localport must be between", dict(localport=0)),
        ("remoteport must be between", dict(remoteport=65536)),
        ("heartbeatdelay must be 0 or more", dict(heartbeatdelay=-1)),
        ("remotename is required", dict(enable=True, localip="192.168.4.1", remoteip="192.168.4.2")),
        ("localip is required", dict(enable=True, remotename="fw2", remoteip="192.168.4.2")),
        ("scert is required with tls", dict(tls=True)),
        ("certificate 'Missing' not found", dict(tls=True, scert="Missing")),
        ("certificate 'No key' has no private key", dict(tls=True, scert="No key")),
        ("mutualtls requires tls", dict(mutualtls=True, ccert="DHCP HA client")),
        ("ccert is required with mutualtls", dict(tls=True, scert="DHCP HA", mutualtls=True)),
    ])
    def test_invalid_option(self, msg, params):
        with set_module_args(params):
            self.assertIn(msg, self.failed()["msg"])
        self.assertFalse(os.path.exists(self.backup_file))
