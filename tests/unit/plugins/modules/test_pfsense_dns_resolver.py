# Copyright: (c) 2024, David Rosado <davidrosza0@gmail.com>
# Copyright: (c) 2025, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.pfsensible.core.plugins.modules import pfsense_dns_resolver
from ansible_collections.pfsensible.core.plugins.modules.pfsense_dns_resolver import PFSenseDNSResolverModule
from .pfsense_module import TestPFSenseModule
from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import patch
from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args


class TestPFSenseDNSResolverModule(TestPFSenseModule):

    module = pfsense_dns_resolver

    def __init__(self, *args, **kwargs):
        super(TestPFSenseDNSResolverModule, self).__init__(*args, **kwargs)
        self.config_file = "pfsense_dns_resolver_config_full.xml"
        self.pfmodule = PFSenseDNSResolverModule

    def setUp(self):
        """ mocking up """

        super(TestPFSenseDNSResolverModule, self).setUp()

        self.mock_php = patch("ansible_collections.pfsensible.core.plugins.module_utils.pfsense.PFSenseModule.php")
        self.php = self.mock_php.start()
        self.php.return_value = {"wan": "WAN", "lan": "LAN", "_llocwan": "WAN IPv6 Link-Local", "_lloclan": "LAN IPv6 Link-Local", "lo0": "Localhost"}

    def check_target_elt(self, obj, target_elt, target_idx=-1):
        """ test the xml definition """
        self.check_param_equal(obj, target_elt, "port")
        self.check_param_bool(obj, target_elt, "enablessl")
        self.check_param_equal(obj, target_elt, "sslcert")
        self.check_param_equal(obj, target_elt, "tlsport")
        # TODO - figure out how these parameters work
        # self.check_param_equal(obj, target_elt, 'active_interface')
        # self.check_param_equal(obj, target_elt, 'outgoing_interface')
        # self.check_param_equal(obj, target_elt, 'system_domain_local_zone_type')
        self.check_param_bool(obj, target_elt, "strictout")
        self.check_param_bool(obj, target_elt, "dnssec", default=True)
        self.check_param_bool(obj, target_elt, "forwarding")
        self.check_param_bool(obj, target_elt, "forward_tls_upstream")
        self.check_param_bool(obj, target_elt, "regdhcp")
        self.check_param_bool(obj, target_elt, "regdhcpstatic")
        self.check_param_bool(obj, target_elt, "regovpnclients")
        self.check_param_equal(obj, target_elt, "custom_options")
        self.check_param_equal(obj, target_elt, "hosts")
        self.check_param_equal(obj, target_elt, "domainoverrides")
        self.check_param_bool(obj, target_elt, "hideidentity", default=True)
        self.check_param_bool(obj, target_elt, "hideversions", default=True)
        self.check_param_bool(obj, target_elt, "prefetch")
        self.check_param_bool(obj, target_elt, "prefetchkey")
        self.check_param_bool(obj, target_elt, "dnssecstripped", default=True)
        self.check_param_equal(obj, target_elt, "msgcachesize", default=4)
        self.check_param_equal(obj, target_elt, "outgoing_num_tcp", default=10)
        self.check_param_equal(obj, target_elt, "incoming_num_tcp", default=10)
        self.check_param_equal(obj, target_elt, "edns_buffer_size", default="auto")
        self.check_param_equal(obj, target_elt, "num_queries_per_thread", default=512)
        self.check_param_equal(obj, target_elt, "jostle_timeout", default=200)
        self.check_param_equal(obj, target_elt, "cache_max_ttl", default=86400)
        self.check_param_equal(obj, target_elt, "cache_min_ttl", default=0)
        self.check_param_equal(obj, target_elt, "infra_host_ttl", default=900)
        self.check_param_equal(obj, target_elt, "infra_cache_numhosts", default=10000)
        self.check_param_equal(obj, target_elt, "unwanted_reply_threshold", default="disabled")
        self.check_param_equal(obj, target_elt, "log_verbosity", default=1)

    def get_target_elt(self, obj, absent=False, module_result=None):
        """ get the generated xml definition """
        return self.assert_find_xml_elt(self.xml_result, "unbound")

    ##############
    # tests
    #
    def test_dns_resolver_init(self):
        """ test init of the DNS Resolver """
        obj = dict()
        command_as_list = ["create dns_resolver pfsense_dns_resolver set enable=True, active_interface='all', "
                           "outgoing_interface='all', custom_options=True, hideidentity=True, hideversion=True, dnssecstripped=True, "
                           "system_domain_local_zone_type='transparent', "
                           "msgcachesize='4', outgoing_num_tcp='10', incoming_num_tcp='10', "
                           "edns_buffer_size='auto', num_queries_per_thread='512', jostle_timeout='200', "
                           "cache_max_ttl='86400', cache_min_ttl='0', infra_host_ttl='900', "
                           "infra_cache_numhosts='10000', unwanted_reply_threshold='disabled', "
                           "log_verbosity='1'"]
        command = "".join(command_as_list)
        self.config_file = "pfsense_dns_resolver_config_init.xml"
        self.do_module_test(obj, command=command)

    def test_dns_resolver_init_with_explicit_values(self):
        """Explicit values take precedence over creation defaults."""
        self.config_file = "pfsense_dns_resolver_config_init.xml"
        obj = dict(dnssec=False, outgoing_num_tcp=0)
        with set_module_args(self.args_from_var(obj)):
            result = self.execute_module(changed=True)
        self.assertNotIn("dnssec", result["diff"]["after"])
        self.assertEqual(result["diff"]["after"]["outgoing_num_tcp"], "0")
        self.assertEqual(result["diff"]["after"]["incoming_num_tcp"], "10")

    def test_dns_resolver_change(self):
        """ test initialization of the DNS Resolver """
        obj = dict(
            active_interface=["lan", "lo0"],
            outgoing_interface=["wan"]
        )
        command_as_list = ["update dns_resolver pfsense_dns_resolver set active_interface='lan,lo0', outgoing_interface='wan'"]
        command = "".join(command_as_list)
        self.do_module_test(obj, command=command)

    def test_dns_resolver_noop(self):
        """ test noop of the DNS Resolver """
        self.config_file = "pfsense_dns_resolver_config.xml"
        self.do_module_test({}, changed=False)

    def test_dns_resolver_partial_update(self):
        """Update a flag and a tuning value while preserving package and resolver settings."""
        self.config_file = "pfsense_dns_resolver_config.xml"
        obj = dict(forwarding=False, log_verbosity=2)
        with set_module_args(self.args_from_var(obj)):
            result = self.execute_module(changed=True)
        before = result["diff"]["before"]
        self.assertEqual(before["python"], "on")
        self.assertEqual(before["python_order"], "post_validator")
        self.assertEqual(before["python_script"], "pfb_unbound.py")
        self.assertTrue(before["custom_options"])
        expected = dict(before, log_verbosity="2")
        del expected["forwarding"]
        self.assertEqual(result["diff"]["after"], expected)

    def test_dns_resolver_explicit_empty_clears_settings(self):
        """Explicit empty arguments clear options and overrides."""
        self.config_file = "pfsense_dns_resolver_config.xml"
        obj = dict(custom_options="", hosts=[], domainoverrides=[])
        with set_module_args(self.args_from_var(obj)):
            result = self.execute_module(changed=True)
        expected = dict(result["diff"]["before"], custom_options="")
        del expected["hosts"]
        del expected["domainoverrides"]
        self.assertEqual(result["diff"]["after"], expected)

    def test_dns_resolver_hosts_reorder_aliases_stay(self):
        """ test that aliases stay with their parent host when hosts are reordered

        Regression test: copy_dict_to_element() pairs list items by position.
        When hosts are provided in a different order than config.xml, a host
        with no aliases could inherit stale <item> children from a host that
        previously occupied the same position.
        """
        # Use a fixture that has two hosts: "server" (with aliases) at position 0,
        # "other" (no aliases) at position 1.
        self.config_file = "pfsense_dns_resolver_config_hosts_aliases.xml"
        self.xml_result = None

        # Provide hosts reversed: other first, server second.
        obj = dict(
            hosts=[
                dict(host="other", domain="example.com", ip="10.0.0.2", descr="", aliases=[]),
                dict(host="server", domain="example.com", ip="10.0.0.1", descr="",
                     aliases=[dict(host="alias1", domain="example.com", description="Alias 1"),
                              dict(host="alias2", domain="example.com", description="Alias 2")]),
            ]
        )
        # Run the module directly and inspect XML — bypass check_target_elt
        # which cannot handle complex nested hosts/aliases structures.
        with set_module_args(self.args_from_var(obj, state="present")):
            self.execute_module(changed=True)
            self.assertTrue(self.load_xml_result())

        # Verify aliases stayed with the correct host after reorder.
        # "other" must have NO alias <item> children; "server" must keep its 2.
        unbound = self.xml_result.find("unbound")
        hosts_elts = unbound.findall("hosts")
        self.assertEqual(len(hosts_elts), 2)

        for host_elt in hosts_elts:
            hostname = host_elt.find("host").text
            aliases_elt = host_elt.find("aliases")
            if hostname == "other":
                items = aliases_elt.findall("item") if aliases_elt is not None else []
                self.assertEqual(len(items), 0,
                                 "Host \"other\" should have no alias items but got %d — "
                                 "aliases bled from \"server\" due to positional matching" % len(items))
            elif hostname == "server":
                items = aliases_elt.findall("item") if aliases_elt is not None else []
                self.assertEqual(len(items), 2,
                                 "Host \"server\" should have 2 alias items but got %d" % len(items))
                self.assertEqual(
                    [{child.tag: child.text for child in item} for item in items],
                    obj["hosts"][1]["aliases"])
            else:
                self.fail("Unexpected host element with hostname %r in result XML" % hostname)

    def test_dns_resolver_preserve_host_aliases(self):
        """ Preserve nested aliases when adding a host. """
        self.config_file = "pfsense_dns_resolver_config_hosts_aliases.xml"
        obj = dict(preserve=True, hosts=[dict(host="new", domain="example.com", ip="10.0.0.3")])
        with set_module_args(self.args_from_var(obj)):
            self.execute_module(changed=True)
            self.assertTrue(self.load_xml_result())
        hosts = self.xml_result.find("unbound").findall("hosts")
        self.assertEqual([host.findtext("host") for host in hosts], ["server", "other", "new"])
        self.assertEqual([item.findtext("host") for item in hosts[0].findall("aliases/item")], ["alias1", "alias2"])
        self.assertEqual(hosts[1].findall("aliases/item"), [])
        self.assertEqual(hosts[2].findall("aliases/item"), [])

    def test_dns_resolver_clear_host_aliases(self):
        """ Explicitly empty aliases remove existing items. """
        self.config_file = "pfsense_dns_resolver_config_hosts_aliases.xml"
        obj = dict(preserve=True, hosts=[dict(host="server", domain="example.com", ip="10.0.0.1", aliases=[])])
        with set_module_args(self.args_from_var(obj)):
            self.execute_module(changed=True)
            self.assertTrue(self.load_xml_result())
        hosts = self.xml_result.find("unbound").findall("hosts")
        self.assertEqual([host.findtext("host") for host in hosts], ["server", "other"])
        self.assertEqual(hosts[0].findall("aliases/item"), [])

    def test_dns_resolver_absent_disables_resolver(self):
        """ state=absent removes the enable flag instead of the unbound root element """
        obj = dict()
        with set_module_args(self.args_from_var(obj, state="absent")):
            self.execute_module(changed=True)
            self.assertTrue(self.load_xml_result())
        unbound = self.xml_result.find("unbound")
        self.assertIsNotNone(unbound)
        self.assertIsNone(unbound.find("enable"))

    def test_dns_resolver_domainoverrides_forward_tls_upstream(self):
        """A domain override with TLS disabled omits the nested flag."""
        obj = dict(
            domainoverrides=[dict(domain="test.example.com", descr="A description", forward_tls_upstream=False, ip="10.0.0.3", tls_hostname="")]
        )
        with set_module_args(self.args_from_var(obj)):
            result = self.execute_module(changed=True)
        override = dict(obj["domainoverrides"][0])
        del override["forward_tls_upstream"]
        self.assertEqual(result["diff"]["after"], dict(result["diff"]["before"], domainoverrides=override))
