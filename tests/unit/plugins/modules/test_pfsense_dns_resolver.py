# Copyright: (c) 2024, David Rosado <davidrosza0@gmail.com>
# Copyright: (c) 2025, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.pfsensible.core.plugins.modules import pfsense_dns_resolver
from ansible_collections.pfsensible.core.plugins.modules.pfsense_dns_resolver import PFSenseDNSResolverModule
from .pfsense_module import TestPFSenseModule
from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import patch


class TestPFSenseDNSResolverModule(TestPFSenseModule):

    module = pfsense_dns_resolver

    def __init__(self, *args, **kwargs):
        super(TestPFSenseDNSResolverModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_dns_resolver_config_full.xml'
        self.pfmodule = PFSenseDNSResolverModule

    def setUp(self):
        """ mocking up """

        super(TestPFSenseDNSResolverModule, self).setUp()

        self.mock_php = patch('ansible_collections.pfsensible.core.plugins.module_utils.pfsense.PFSenseModule.php')
        self.php = self.mock_php.start()
        self.php.return_value = {'wan': 'WAN', 'lan': 'LAN', '_llocwan': 'WAN IPv6 Link-Local', '_lloclan': 'LAN IPv6 Link-Local', 'lo0': 'Localhost'}

    def check_target_elt(self, obj, target_elt, target_idx=-1):
        """ test the xml definition """
        self.check_param_equal(obj, target_elt, 'port')
        self.check_param_bool(obj, target_elt, 'enablessl')
        self.check_param_equal(obj, target_elt, 'sslcert')
        self.check_param_equal(obj, target_elt, 'tlsport')
        # TODO - figure out how these parameters work
        # self.check_param_equal(obj, target_elt, 'active_interface')
        # self.check_param_equal(obj, target_elt, 'outgoing_interface')
        # self.check_param_equal(obj, target_elt, 'system_domain_local_zone_type')
        self.check_param_bool(obj, target_elt, 'dnssec', default=True)
        self.check_param_bool(obj, target_elt, 'forwarding')
        self.check_param_bool(obj, target_elt, 'forward_tls_upstream')
        self.check_param_bool(obj, target_elt, 'regdhcp')
        self.check_param_bool(obj, target_elt, 'regdhcpstatic')
        self.check_param_bool(obj, target_elt, 'regovpnclients')
        self.check_param_equal(obj, target_elt, 'custom_options')
        self.check_param_equal(obj, target_elt, 'hosts')
        self.check_param_equal(obj, target_elt, 'domainoverrides')
        self.check_param_bool(obj, target_elt, 'hideidentity', default=True)
        self.check_param_bool(obj, target_elt, 'hideversions', default=True)
        self.check_param_bool(obj, target_elt, 'prefetch')
        self.check_param_bool(obj, target_elt, 'prefetchkey')
        self.check_param_bool(obj, target_elt, 'dnssecstripped', default=True)
        self.check_param_equal(obj, target_elt, 'msgcachesize', default=4)
        self.check_param_equal(obj, target_elt, 'outgoing_num_tcp', default=10)
        self.check_param_equal(obj, target_elt, 'incoming_num_tcp', default=10)
        self.check_param_equal(obj, target_elt, 'edns_buffer_size', default="auto")
        self.check_param_equal(obj, target_elt, 'num_queries_per_thread', default=512)
        self.check_param_equal(obj, target_elt, 'jostle_timeout', default=200)
        self.check_param_equal(obj, target_elt, 'cache_max_ttl', default=86400)
        self.check_param_equal(obj, target_elt, 'cache_min_ttl', default=0)
        self.check_param_equal(obj, target_elt, 'infra_host_ttl', default=900)
        self.check_param_equal(obj, target_elt, 'infra_cache_numhosts', default=10000)
        self.check_param_equal(obj, target_elt, 'unwanted_reply_threshold', default="disabled")
        self.check_param_equal(obj, target_elt, 'log_verbosity', default=1)

    def get_target_elt(self, obj, absent=False, module_result=None):
        """ get the generated xml definition """
        return self.assert_find_xml_elt(self.xml_result, 'unbound')

    ##############
    # tests
    #
    def test_dns_resolver_init(self):
        """ test init of the DNS Resolver """
        obj = dict()
        command_as_list = ["update dns_resolver pfsense_dns_resolver set active_interface='all', "
                           "outgoing_interface='all', system_domain_local_zone_type='transparent', "
                           "msgcachesize='4', outgoing_num_tcp='10', incoming_num_tcp='10', "
                           "edns_buffer_size='auto', num_queries_per_thread='512', jostle_timeout='200', "
                           "cache_max_ttl='86400', cache_min_ttl='0', infra_host_ttl='900', "
                           "infra_cache_numhosts='10000', unwanted_reply_threshold='disabled', "
                           "log_verbosity='1'"]
        command = "".join(command_as_list)
        self.config_file = 'pfsense_dns_resolver_config_init.xml'
        self.do_module_test(obj, command=command)

    def test_dns_resolver_change(self):
        """ test initialization of the DNS Resolver """
        obj = dict(
            active_interface=['lan', 'lo0'],
            outgoing_interface=['wan']
        )
        command_as_list = ["update dns_resolver pfsense_dns_resolver set active_interface='lan,lo0', outgoing_interface='wan'"]
        command = "".join(command_as_list)
        self.do_module_test(obj, command=command)

    def test_dns_resolver_noop(self):
        """ test noop of the DNS Resolver """
        obj = dict()
        self.do_module_test(obj, changed=False)

    def test_dns_resolver_domainoverrides_forward_tls_upstream(self):
        """ test initialization of the DNS Resolver """
        obj = dict(
            domainoverrides=[dict(domain="test.example.com", descr="A description", forward_tls_upstream=False, ip="10.0.0.3", tls_hostname='')]
        )
        command_as_list = ["update dns_resolver pfsense_dns_resolver set "]
        command = "".join(command_as_list)
        expected_elt_string = """<unbound>
		<enable></enable>
		<dnssec></dnssec>
		<active_interface>all</active_interface>
		<outgoing_interface>all</outgoing_interface>
		<custom_options></custom_options>
		<hideidentity></hideidentity>
		<hideversion></hideversion>
		<dnssecstripped></dnssecstripped>
		<qname-minimisation></qname-minimisation>
		<system_domain_local_zone_type>transparent</system_domain_local_zone_type>
		<msgcachesize>4</msgcachesize>
		<outgoing_num_tcp>10</outgoing_num_tcp>
		<incoming_num_tcp>10</incoming_num_tcp>
		<edns_buffer_size>auto</edns_buffer_size>
		<num_queries_per_thread>512</num_queries_per_thread>
		<jostle_timeout>200</jostle_timeout>
		<cache_max_ttl>86400</cache_max_ttl>
		<cache_min_ttl>0</cache_min_ttl>
		<infra_host_ttl>900</infra_host_ttl>
		<infra_cache_numhosts>10000</infra_cache_numhosts>
		<unwanted_reply_threshold>disabled</unwanted_reply_threshold>
		<log_verbosity>1</log_verbosity>
		<domainoverrides>
			<domain>test.example.com</domain>
			<descr>A description</descr>
			<ip>10.0.0.3</ip>
			<tls_hostname></tls_hostname>
		</domainoverrides>
	</unbound>
	"""  # noqa: E101,W191
        self.do_module_test(obj, command=command, expected_elt_string=expected_elt_string)
