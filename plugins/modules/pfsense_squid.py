#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2021, Jan Wenzel <jan.wenzel@gonicus.de>
# Copyright: (c) 2022, Geno <geno+dev@fireorbit.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_squid
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage squid http proxy settings
description:
  - Manage pfSense squid http proxy settings
notes:
options:
  auth:
    description: Squid Authentication Config
    type: dict
    suboptions:
      auth_method:
        description: Authentication Method
        type: str
        choices: ["none", "local", "ldap", "radius", "cp"]
        default: none
      auth_server:
        description: Authentication Server
        type: str
      auth_server_port:
        description: Authentication Server Port
        type: int
      auth_prompt:
        description: Authentication Prompt
        type: str
        default: "Please enter your credentials to access the proxy"
      auth_processes:
        description: Authentication Processes
        type: int
        default: 5
      auth_ttl:
        description: Authentication Time-To-Live
        type: int
        default: 5
      max_user_ip:
        description: Authentication Max User IP Addresses
        type: int
      unrestricted_auth:
        description: Required Authentication for Unrestricted IPs
        type: bool
      no_auth_hosts:
        description: Subnets That Don't Need Authentication
        type: list
        elements: str
      ldap_version:
        description: LDAP Version
        type: int
        choices: [2, 3]
        default: 2
      ldap_urltype:
        description: LDAP Transport
        type: str
        choices: ["standard", "starttls", "ssl"]
        default: standard
      ldap_user:
        description: LDAP Server User DN
        type: str
      ldap_pass:
        description: LDAP Password
        type: str
      ldap_basedomain:
        description: LDAP Base Domain
        type: str
      ldap_userattribute:
        description: LDAP Username DN Attribute
        type: str
        default: uid
      ldap_filter:
        description: LDAP Search Filter
        type: str
        default: (&(objectClass=person)(uid=%s))
      ldap_noreferrals:
        description: LDAP not follow referrals
        type: bool
  antivirus:
    description: Squid Antivirus Config
    type: dict
    suboptions:
      enable:
        description: Enable Antivirus
        type: bool
      client_info:
        description: Client Forward Options
        type: str
        choices: ["both", "username", "ip", "none"]
        default: both
      enable_advanced:
        description: Enable Manual Configuration
        type: bool
        default: False
      clamav_url:
        description: Redirect URL
        type: str
        default: emtpy for Squid/pfSense WebGUI URL
      clamav_scan_type:
        description: Scan Type
        type: str
        choices: ["all", "web", "app"]
        default: all
      clamav_disable_stream_scanning:
        description: Exclude Audio/Video Streams
        type: bool
      clamav_block_pua:
        description: Block Potentially Unwanted Applications
        type: bool
      clamav_update:
        description: ClamAV Database Update (hours)
        type: int
        choices: [0, 1, 2, 3, 4, 6, 8, 12, 24]
        default: 0
      clamav_dbregion:
        description: Regional ClamAV Database Update Mirror
        type: str
        choices: ["", "au", "europe", "ca", "cn", "id", "jp", "kr", "ml", "ru", "sa", "tw", "uk", "us"]
        default: ""
      clamav_dbservers:
        description: Optional ClamAV Database Update Servers
        type: list
        elements: str
      urlhaus_sig:
        description: Enables URLhaus active malware distribution sites DB support.
        type: bool
      interserver_sig:
        description: Enables InterServer.net malware DB support
        type: bool
      securiteinfo_sig:
        description: Enables SecuriteInfo.com malware DB support
        type: bool
      securiteinfo_premium:
        description: Enables SecuriteInfo.com 0-day malware DB support
        type: bool
      securiteinfo_id:
        description: SecuriteInfo ID
        type: str
      raw_squidclamav_conf:
        description: Contents of squidclamav.conf
        type: str
      raw_cicap_conf:
        description: Contents of c-icap.conf
        type: str
      raw_cicap_magic:
        description: Contents of c-icap.magic
        type: str
      raw_freshclam_conf:
        description: Contents of freshclam.conf
        type: str
      raw_clamd_conf:
        description: Contents of clamd.conf
        type: str
  cache:
    description: Squid Local Cache Config
    type: dict
    suboptions:
      nocache:
        description: Disable caching completely
        type: bool
      cache_replacement_policy:
        description: Cache Replacement Policy
        type: str
        choices: ["heap LFUDA", "heap GDSF", "heap LRU", "LRU"]
        default: "heap LFUDA"
      cache_swap_low:
        description: Low-Water Mark in %
        type: int
        default: 90
      cache_swap_high:
        description: High-Water Mark in %
        type: int
        default: 95
      donotcache:
        description: Domain(s) and/or IP address(es) that should never be cached
        type: list
        elements: str
      enable_offline:
        description: Enable Offline Mode
        type: bool
      ext_cachemanager:
        description: IPs of external cache managers
        type: list
        elements: str
      harddisk_cache_size:
        description: Hard Disk Cache Size (MB)
        type: int
        default: 100
      harddisk_cache_system:
        description: Kind of storage system to use
        type: str
        choices: ["aufs", "diskd", "null", "ufs"]
        default: ufs
      level1_subdirs:
        description: Level 1 Directories
        type: int
        choices: [4, 8, 16, 32, 64, 128, 256]
        default: 16
      harddisk_cache_location:
        description: Hard Disk Cache Location
        type: path
        default: /var/squid/cache
      minimum_object_size:
        description: Minimum Object Size (KB)
        type: int
        default: 0
      maximum_object_size:
        description: Maximum Object Size (MB)
        type: int
        default: 4
      memory_cache_size:
        description: Memory Cache Size (MB)
        type: int
        default: 64
      maximum_objsize_in_mem:
        description: Maximum Object Size in RAM (KB)
        type: int
        default: 256
      memory_replacement_policy:
        description: Memory Replacement Policy
        type: str
        choices: ["heap GDSF", "heap LFUDA", "heap LRU", "LRU"]
        default: "heap GDFS"
      cache_dynamic_content:
        description: Cache Dynamic Content
        type: bool
      custom_refresh_patterns:
        description: Custom Refresh Patterns
        type: list
        elements: str
  general:
    description: General Squid Config
    type: dict
    suboptions:
      enable_squid:
        description: Enable Squid HTTP Proxy
        type: bool
      keep_squid_data:
        description: If enabled, the settings, logs, cache, AV defs and other data will be preserved across package reinstalls.
        type: bool
      listenproto:
        description: Listen IP Version
        type: str
        choices: [ "inet", "inet6", "any"]
        default: inet
      carpstatusvid:
        description: CARP Status VIP
        type: str
      active_interface:
        description: Proxy Interface(s)
        type: list
        elements: str
        default: ["lan"]
      outgoing_interface:
        description: Outgoing Network Interface
        type: str
        default: lan
      proxy_port:
        description: Proxy Port
        type: int
        default: 3128
      icp_port:
        description: ICP Port
        type: int
      allow_interface:
        description: Allow Users on Interface
        type: bool
        default: True
      dns_v4_first:
        description: Resolve DNS IPv4 First
        type: bool
      disable_pinger:
        description: Disable ICMP
        type: bool
      dns_nameservers:
        description: Use Alternate DNS Servers for the Proxy Server
        type: list
        elements: str
      extraca:
        description: Extra Trusted CA
        type: str
      transparent_proxy:
        description: Enable Transparent HTTP Proxy
        type: bool
      transparent_active_interface:
        description: Transparent Proxy Interface(s)
        type: list
        elements: str
      private_subnet_proxy_off:
        description: Bypass Proxy for Private Address Destination
        type: bool
      defined_ip_proxy_off:
        description: Bypass Proxy for These Source IPs
        type: list
        elements: str
      defined_ip_proxy_off_dest:
        description: Bypass Proxy for These Destination IPs
        type: list
        elements: str
      ssl_proxy:
        description: Enable HTTPS/SSL Interception
        type: bool
      sslproxy_mitm_mode:
        description: SSL/MITM Mode
        type: str
        choices: ["splicewhitelist", "spliceall", "custom"]
        default: splicewhitelist
      ssl_active_interface:
        description: SSL Intercept Interface(s)
        type: list
        elements: str
      ssl_proxy_port:
        description: SSL Proxy Port while using transparent mode
        type: int
        default: 3129
      sslproxy_compatibility_mode:
        description: SSL Proxy Compatibility Mode
        type: str
        choices: ["modern", "intermediate"]
        default: modern
      dhparams_size:
        description: DHParams Key Size
        type: int
        choices: [1024, 2048, 4096]
        default: 2048
      dca:
        description: Certificate Authority
        type: str
      sslcrtd_children:
        description: SSL Certificate Daemon Children
        type: int
        default: 5
      interception_checks:
        description: Remote Cert Checks
        type: list
        elements: str
        choices: ["sslproxy_cert_error", "sslproxy_flags"]
      interception_adapt:
        description: Certificate Adapt
        type: list
        elements: str
        choices: ["setValidAfter", "setValidBefore", "setCommonName"]
      log_enabled:
        description: Enable Access Logging
        type: bool
      log_dir:
        description: Log Store Directory
        type: path
        default: /var/squid/logs
      log_rotate:
        description: Rotate Logs (days)
        type: int
      log_sqd:
        description: Log Pages Denied by SquidGuard
        type: bool
      visible_hostname:
        description: Visible Hostname
        type: str
        default: localhost
      admin_email:
        description: Administrator'r email
        type: str
        default: admin@localhost
      error_language:
        description: Error Language
        type: str
        choices: ["af", "ar", "az", "bg", "ca", "cs", "da", "de",
                  "el", "en", "es", "et", "fa", "fi", "fr", "he",
                  "hu", "hy", "id", "it", "ja", "ko", "lt", "lv",
                  "ms", "nl", "oc", "pl", "pt", "pt-br", "ro",
                  "ru", "sk", "sl", "sr-cyrl", "sr-latn", "sv",
                  "th", "tr", "uk", "uz", "vi", "zh-cn", "zh-tw"]
        default: en
      xforward_mode:
        description: X-Forwarded Header Mode
        type: str
        choices: ["on", "off", "transparent", "delete", "truncate"]
        default: on
      disable_via:
        description: Disable VIA Header
        type: bool
      uri_whitespace:
        description: URI Whitespace Characters Handling
        type: str
        choices: ["allow", "chop", "deny", "encode", "strip"]
        default: strip
      disable_squidversion:
        description: Suppress Squid Version
        type: bool
      custom_options:
        description: Integrations
        type: str
      custom_options_squid3:
        description: Custome Options (Before Auth)
        type: str
      custom_options2_squid3:
        description: Custome Options (After Auth)
        type: str
      custom_options3_squid3:
        description: Custome Options (SSL/MITM)
        type: str
  nac:
    description: Network Access Control Squid Config
    type: dict
    suboptions:
      allowed_subnets:
        description: Allowed Subnets
        type: list
        elements: str
      unrestricted_hosts:
        description: Unrestricted IPs
        type: list
        elements: str
      banned_hosts:
        description: Banned Hosts Addresses
        type: list
        elements: str
      whitelist:
        description: Whitelist
        type: list
        elements: str
      blacklist:
        description: Blacklist
        type: list
        elements: str
      block_user_agent:
        description: Block User Agents
        type: list
        elements: str
      block_reply_mime_type:
        description: Block MIME Types (Reply Only)
        type: list
        elements: str
      addtl_ports:
        description: ACL SafePorts (in addition to 21,70,80,210,280,443,488,563,591,631,777,901,1025-65535)
        type: list
        elements: int
      addtl_sslports:
        description: ACL SSLPorts (in addition to 443,563)
        type: list
        elements: int
      google_accounts:
        description: Google Accounts Domains
        type: list
        elements: str
      youtube_restrict:
        description: Youtube Restrictions
        type: str
        choices: ["none", "moderate", "strict"]
  remote:
    description: Remote Cache Squid Settings
    type: list
    elements: dict
    suboptions:
      state:
        description: Should the remote be defined
        type: str
        choices: ["present", "absent"]
        default: present
      enable:
        description: Enable Remote
        type: bool
      proxyaddr:
        description: Hostname
        type: str
      proxyname:
        description: Unique Remote Identifier
        type: str
      proxyport:
        description: TCP Port
        type: int
        default: 3128
      allowmiss:
        description: General Options
        type: list
        elements: str
        choices: ["allow-miss", "no-tproxy", "proxy-only"]
        default: ["allow-miss"]
      hierarchy:
        description: Hierarchy
        type: str
        choices: ["sibling", "parent", "multicast"]
        default: parent
      peermethod:
        description: Peer Method
        type: str
        choices: ["round-robin", "default", "weighted-round-robin", "carp", "userhash", "sourcehash", "multicast-sibling"]
        default: round-robin
      weight:
        description: Weight
        type: int
        default: 1
      basetime:
        description: Basetime
        type: int
        default: 1
      ttl:
        description: TTL
        type: int
        default: 1
      nodelay:
        description: No Delay
        type: bool
        default: False
      icpport:
        description: Remote ICP Port (7 means disabled)
        type: int
        default: 7
      icpoptions:
        description: ICP Options
        type: str
        choices: ["no-query", "multicast-responder", "closest-only", "background-ping"]
        default: no-query
      username:
        description: Upstream Username
        type: str
      password:
        description: Upstream Password
        type: str
      authoption:
        description: Authentication Options
        type: str
        choices: ["login=*:password", "login=user:password", "login=PASSTHRU", "login=PASS", "login=NEGOTIATE", "login=NEGOTIATE:principal_name", "connection-auth=on", "connection-auth=off"]
        default: login=*:password
  sync:
    description: Squid XMLRPC Sync Settings
    type: dict
    suboptions:
      synconchanges:
        description: Enable Sync
        type: str
        choices: ["auto", "disabled", "manual"]
        default: disabled
      synctimeout:
        description: Sync Timeout (s)
        type: int
        choices: [30, 60, 90, 120, 250]
        default: 250
      synctargets:
        description: Replication Targets (manual mode)
        type: list
        elements: dict
        suboptions:
          syncdestinable:
            description: Enable Sync Target
            type: bool
          syncprotocol:
            description: XMLRPC Sync Protocol
            type: str
            choices: ["http", "https"]
            default: http
          ipaddress:
            description: IP Address / Hostname
            type: str
            required: true
          syncport:
            description: HTTP/HTTPS Port
            type: int
          username:
            description: Remote Username
            type: str
            required: true
          password:
            description: Remote Password
            type: str
            required: true
  traffic:
    description: Traffic Management Administration
    type: dict
    suboptions:
      max_download_size:
        description: Maximum Download Size in kilobytes (0 = disabled)
        type: int
        default: 0
      max_upload_size:
        description: Maximum Upload Size in kilobytes(0 = disabled)
        type: int
        default: 0
      overall_throttling:
        description: Overall Bandwidth Throttling in kilobytes (0 = disabled)
        type: int
        default: 0
      perhost_throttling:
        description: Download Throttling per host in kilobytes (0 = disabled)
        type: int
        default: 0
      unrestricted_throttling:
        description: Throttle Unrestricted IPs
        type: bool
        default: false
      throttle_specific:
        description: Throttle Only Specific Extensions
        type: bool
        default: false
      throttle_binaries:
        description: Throttle Binary Files
        type: bool
        default: false
      throttle_cdimages:
        description: Throttle DC/DVD Image Files
        type: bool
        default: false
      throttle_multimedia:
        description: Throttle Multimedia Files
        type: bool
        default: false
      throttle_others:
        description: Throttle Other Extensions
        type: list
        elements: str
      quick_abort_min:
        description: Finish transfer if less than x KB remaining
        type: int
        default: 0
      quick_abort_max:
        description: Finish transfer if more than x KB remaining
        type: int
        default: 0
      quick_abort_pct:
        description: Finish transfer if more than x % finished
        type: int
        default: 0
  users:
    description: Local Squid User Administration
    type: list
    elements: dict
    suboptions:
      state:
        description: Should the user be present or absent
        type: str
        choices: ["present", "absent"]
        default: present
      username:
        description: Username
        type: str
        required: True
      password:
        description: Password
        type: str
        required: True
      description:
        description: Description of User
        type: str
"""

EXAMPLES = """
- name: setup dns resolver to use forwarders
  pfsense_dns_resolver:
    enable: true
    forwarding: true
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["update dns_resolver set enable='true', forwarding='true'"]
"""

import base64
from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.pfsense import PFSenseModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

base64_params = [
  'allowed_subnets',
  'banned_hosts',
  'blacklist',
  'block_user_agent',
  'block_reply_mime_type',
  'custom_options_squid3',
  'custom_options2_squid3',
  'custom_options3_squid3',
  'custom_refresh_patterns',
  'donotcache',
  'no_auth_hosts',
  'raw_squidclamav_conf',
  'raw_cicap_conf',
  'raw_cicap_magic',
  'raw_freshclam_conf',
  'raw_clamd_conf',
  'unrestricted_hosts',
  'whitelist',
]

cert_params = [
  'dca',
  'extraca',
]

SQUID_CONFIG_AUTH_ARGUMENT_SPEC = dict(
  auth_method=dict(required=False, type='str', choices=[
    'none',
    'local',
    'ldap',
    'radius',
    'cp',
  ], default='none'),
  auth_server=dict(required=False, type='str'),
  auth_server_port=dict(required=False, type='int'),
  auth_prompt=dict(required=False, type='str', default='Please enter your credentials to access the proxy'),
  auth_processes=dict(required=False, type='int', default=5),
  auth_ttl=dict(required=False, type='int', default=5),
  max_user_ip=dict(required=False, type='int'),
  unrestricted_auth=dict(required=False, type='bool'),
  no_auth_hosts=dict(required=False, type='list', elements='str'),
  ldap_version=dict(required=False, type='int', choices=[2, 3], default=2),
  ldap_urltype=dict(required=False, type='str', choices=[
    'standard',
    'starttls',
    'ssl',
  ], default='standard'),
  ldap_user=dict(required=False, type='str'),
  ldap_pass=dict(required=False, type='str', no_log=True),
  ldap_basedomain=dict(required=False, type='str'),
  ldap_userattribute=dict(required=False, type='str', default='uid'),
  ldap_filter=dict(required=False, type='str', default='(&(objectClass=person)(uid=%s))'),
  ldap_noreferrals=dict(required=False, type='str'),
  radius_secret=dict(required=False, type='str', no_log=True),
)

SQUID_CONFIG_ANTIVIRUS_ARGUMENT_SPEC = dict(
  enable=dict(required=False, type='bool'),
  client_info=dict(required=False, type='str', choices=[
    'both',
    'username',
    'ip',
    'none',
  ], default='both'), 
  enable_advanced=dict(required=False, type='bool', default=False),
  clamav_url=dict(required=False, type='str'),
  clamav_scan_type=dict(required=False, type='str', choices=[
    'all',
    'app',
    'web',
  ], default='all'),
  clamav_disable_stream_scanning=dict(required=False, type='bool'),
  clamav_block_pua=dict(required=False, type='bool'),
  clamav_update=dict(required=False, type='int', choices=[
    0, 1, 2, 3, 4, 6, 8, 12, 24
  ], default=0),
  clamav_dbregion=dict(required=False, type='str', choices=[
    '', 'au', 'europe', 'ca', 'cn', 'id', 'jp',
    'kr', 'ml', 'ru', 'sa', 'tw', 'uk', 'us',
  ]),
  clamav_dbservers=dict(required=False, type='list', elements='str'),
  urlhaus_sig=dict(required=False, type='bool'),
  interserver_sig=dict(required=False, type='bool'),
  securiteinfo_sig=dict(required=False, type='bool'),
  securiteinfo_premium=dict(required=False, type='bool'),
  securiteinfo_id=dict(required=False, type='str'),
  raw_squidclamav_conf=dict(required=False, type='str'),
  raw_cicap_conf=dict(required=False, type='str'),
  raw_cicap_magic=dict(required=False, type='str'),
  raw_freshclam_conf=dict(required=False, type='str'),
  raw_clamd_conf=dict(required=False, type='str'),
)

SQUID_CONFIG_CACHE_ARGUMENT_SPEC = dict(
  nocache=dict(required=False, type='bool'),
  cache_replacement_policy=dict(required=False, type='str', choices=[
    'heap LFUDA',
    'heap GDSF',
    'heap LRU',
    'LRU',
  ], default='heap LFUDA'),
  cache_swap_low=dict(required=False, type='int', default=90),
  cache_swap_high=dict(required=False, type='int', default=95),
  donotcache=dict(required=False, type='list', elements='str'),
  enable_offline=dict(required=False, type='bool'),
  ext_cachemanager=dict(required=False, type='list', elements='str'),
  harddisk_cache_size=dict(required=False, type='int', default=100),
  harddisk_cache_system=dict(required=False, type='str', choices=[
    'aufs',
    'diskd',
    'null',
    'ufs',
  ], default='ufs'),
  level1_subdirs=dict(required=False, type='int', choices=[
    4, 8, 16, 32, 64, 128, 256,
  ], default=16),
  harddisk_cache_location=dict(required=False, type='path', default='/var/squid/cache'),
  minimum_object_size=dict(required=False, type='int', default=0),
  maximum_object_size=dict(required=False, type='int', default=4),
  memory_cache_size=dict(required=False, type='int', default=64),
  maximum_objsize_in_mem=dict(required=False, type='int', default=256),
  memory_replacement_policy=dict(required=False, type='str', choices=[
    'heap GDSF',
    'heap LFUDA',
    'heap LRU',
    'LRU',
  ], default='heap GDSF'),
  cache_dynamic_content=dict(required=False, type='bool'),
  custom_refresh_patterns=dict(required=False, type='list', elements='str'),
)

SQUID_CONFIG_GENERAL_ARGUMENT_SPEC = dict(
  enable_squid=dict(required=False, type='bool'),
  keep_squid_data=dict(required=False, type='bool', default=True),
  listenproto=dict(required=False, type='str', choices=[
    'inet',
    'inet6',
    'any'], 
    default='inet'),
  carpstatusvid=dict(required=False, type='str'),
  active_interface=dict(required=False, type='list', elements='str', default=['lan']),
  outgoing_interface=dict(required=False, type='str', default='lan'),
  proxy_port=dict(required=False, type='int', default=3128),
  icp_port=dict(required=False, type='int'),
  allow_interface=dict(required=False, type='bool', default=True),
  dns_v4_first=dict(required=False, type='bool'),
  disable_pinger=dict(required=False, type='bool'),
  dns_nameservers=dict(required=False, type='list', elements='str'),
  extraca=dict(required=False, type='str'),
  transparent_proxy=dict(required=False, type='bool'),
  transparent_active_interface=dict(required=False, type='list', elements='str'),
  private_subnet_proxy_off=dict(required=False, type='bool'),
  defined_ip_proxy_off=dict(required=False, type='list', elements='str'),
  defined_ip_proxy_off_dest=dict(required=False, type='list', elements='str'),
  ssl_proxy=dict(required=False, type='bool'),
  sslproxy_mitm_mode=dict(required=False, type='str', choices=[
    'splicewhitelist',
    'spliceall',
    'custom',
  ], default='splicewhitelist'),
  ssl_active_interface=dict(required=False, type='list', elements='str', default=['lan']),
  ssl_proxy_port=dict(required=False, type='int', default=3129),
  sslproxy_compatibility_mode=dict(required=False, type='str', choices=[
    'modern',
    'intermediate',
  ], default='modern'),
  dhparams_size=dict(required=False, type='int', choices=[
    1024,
    2048,
    4096,
  ], default=2048),
  dca=dict(required=False, type='str'),
  sslcrtd_children=dict(required=False, type='int', default=5),
  interception_checks=dict(required=False, type='list', elements='str', choices=[
    'sslproxy_cert_error',
    'sslproxy_flags',
  ]),
  interception_adapt=dict(required=False, type='list', elements='str', choices=[
    'setValidAfter',
    'setValidBefore',
    'setCommonName',
  ]),
  log_enabled=dict(required=False, type='bool'),
  log_dir=dict(required=False, type='path', default='/var/squid/logs'),
  log_rotate=dict(required=False, type='int'),
  log_sqd=dict(required=False, type='bool'),
  visible_hostname=dict(required=False, type='str', default='localhost'),
  admin_email=dict(required=False, type='str', default='admin@localhost'),
  error_language=dict(required=False, type='str', choices=[
    'af', 'ar', 'az', 'bg', 'ca', 'cs', 'da', 'de',
    'el', 'en', 'es', 'et', 'fa', 'fi', 'fr', 'he',
    'hu', 'hy', 'id', 'it', 'ja', 'ko', 'lt', 'lv',
    'ms', 'nl', 'oc', 'pl', 'pt', 'pt-br', 'ro',
    'ru', 'sk', 'sl', 'sr-cyrl', 'sr-latn', 'sv',
    'th', 'tr', 'uk', 'uz', 'vi', 'zh-cn', 'zh-tw',
  ], default='en'),
  xforward_mode=dict(required=False, type='str', choices=[
    'on',
    'off',
    'transparent',
    'delete',
    'truncate',
  ], default='on'),
  disable_via=dict(required=False, type='bool'),
  uri_whitespace=dict(required=False, type='str', choices=[
    'allow',
    'chop',
    'deny',
    'encode',
    'strip',
  ], default='strip'),
  disable_squidversion=dict(required=False, type='bool'),
  custom_options=dict(required=False, type='str'),
  custom_options_squid3=dict(required=False, type='str'),
  custom_options2_squid3=dict(required=False, type='str'),
  custom_options3_squid3=dict(required=False, type='str'),
)

SQUID_CONFIG_NAC_ARGUMENT_SPEC = dict(
  allowed_subnets=dict(type='list', elements='str'),
  unrestricted_hosts=dict(type='list', elements='str'),
  banned_hosts=dict(type='list', elements='str'),
  whitelist=dict(type='list', elements='str'),
  blacklist=dict(type='list', elements='str'),
  block_user_agent=dict(type='list', elements='str'),
  block_reply_mime_type=dict(type='list', elements='str'),
  addtl_ports=dict(type='list', elements='int'),
  addtl_sslports=dict(type='list', elements='int'),
  google_accounts=dict(type='list', elements='str'),
  youtube_restrict=dict(type='str', choices=[
    'none',
    'moderate',
    'strict',
  ]),
)

SQUID_CONFIG_REMOTE_ARGUMENT_SPEC = dict(
  state=dict(required=False, type='str', default='present'),
  enable=dict(required=False, type='bool', default=False),
  proxyaddr=dict(required=False, type='str'),
  proxyname=dict(required=False, type='str'),
  proxyport=dict(required=False, type='int', default=3128),
  allowmiss=dict(required=False, type='list', elements='str', choices=[
    'allow-miss',
    'no-tproxy',
    'proxy-only',
  ], default=['allow-miss']),
  hierarchy=dict(required=False, type='str', choices=[
    'sibling',
    'parent',
    'multicast',
  ], default='parent'),
  peermethod=dict(required=False, type='str', choices=[
    'round-robin',
    'default',
    'weighted-round-robin',
    'carp',
    'userhash',
    'sourcehash',
    'multicast-sibling',
  ], default='round-robin'),
  weight=dict(required=False, type='int', default=1),
  basetime=dict(required=False, type='int', default=1),
  ttl=dict(required=False, type='int', default=1),
  nodelay=dict(required=False, type='bool', default=False),
  icpport=dict(required=False, type='int', default=7),
  icpoptions=dict(required=False, type='str', choices=[
    'no-query',
    'multicast-responder',
    'closest-only',
    'background-ping',
  ], default='no-query'),
  username=dict(required=False, type='str'),
  password=dict(required=False, type='str', no_log=True),
  authoption=dict(required=False, type='str', choices=[
    'login=*:password',
    'login=user:password',
    'login=PASSTHRU',
    'login=PASS',
    'login=NEGOTIATE',
    'login=NEGOTIATE:principal_name',
    'connection-auth=on',
    'connection-auth=off',
  ], default='login=*:password')
)

SQUID_CONFIG_SYNC_TARGET_ARGUMENT_SPEC = dict(
  syncdestinenable=dict(type='bool'),
  syncprotocol=dict(type='str', choices=[
    'http',
    'https'
  ], default='http'),
  ipaddress=dict(required=True, type='str'),
  syncport=dict(required=False, type='int'),
  username=dict(required=True, type='str'),
  password=dict(required=True, type='str', no_log=True),
)

SQUID_CONFIG_SYNC_ARGUMENT_SPEC = dict(
  synconchanges=dict(type='str', choices=[
    'auto',
    'disabled',
    'manual',
  ], default='disabled'),
  synctimeout=dict(type='int', choices=[
    30, 60, 90, 120, 250,
  ], default=250),
  synctargets=dict(type='list', elements='dict',
    options=SQUID_CONFIG_SYNC_TARGET_ARGUMENT_SPEC,
  ),
)
      
SQUID_CONFIG_TRAFFIC_ARGUMENT_SPEC = dict(
  max_download_size=dict(type='int', default=0),
  max_upload_size=dict(type='int', default=0),
  overall_throttling=dict(type='int', default=0),
  perhost_throttling=dict(type='int', default=0),
  unrestricted_throttling=dict(type='bool', default=False),
  throttle_specific=dict(type='bool', default=False),
  throttle_binaries=dict(type='bool', default=False),
  throttle_cdimages=dict(type='bool', default=False),
  throttle_multimedia=dict(type='bool', default=False),
  throttle_others=dict(type='list', elements='str'),
  quick_abort_min=dict(type='int', default=0),
  quick_abort_max=dict(type='int', default=0),
  quick_abort_pct=dict(type='int', default=0),
)

SQUID_CONFIG_USER_ARGUMENT_SPEC = dict(
  state=dict(required=False, type='str', default='present'),
  username=dict(required=True, type='str'),
  password=dict(required=True, type='str', no_log=True),
  description=dict(required=False, type='str'),
)

class PFSenseSquidConfigAuthModule(PFSenseModuleBase):
  @staticmethod
  def get_argument_spec():
    """ return argument spec """
    return SQUID_CONFIG_AUTH_ARGUMENT_SPEC(PFSenseModuleBase)
  
  def __init__(self, module, pfsense=None):
    super(PFSenseSquidConfigAuthModule, self).__init__(module, pfsense)
    self.name = "pfsense_squid_config"
    self.obj = dict()
    self.before = None
    self.before_elt = None
    pkgs_elt = self.pfsense.get_element('installedpackages')
    squidauth_elt = self.pfsense.get_element('squidauth', pkgs_elt, create_node=True)
    self.root_elt = self.pfsense.get_element('config', squidauth_elt, create_node=True)

  def _params_to_obj(self):
    """ return a dict from module params """
    params = self.params
    obj = self.pfsense.element_to_dict(self.root_elt)
    self.before = deepcopy(obj)
    self.before_elt = deepcopy(self.root_elt)

    def _set_param(target, param):
      if params.get(param) is not None:
        if isinstance(params[param], str):
          if param in base64_params:
            target[param] = base64.b64encode(params[param])
          else:
            target[param] = params[param]
        else:
          if param in base64_params:
            target[param] = base64.b64encode('\n'.join(params[param]).encode()).decode()
          else:
            target[param] = str(params[param])

    def _set_param_bool(target, param):
      if params.get(param) is not None:
        value = params.get(param)
        if value is True and (param not in target or target[param] != 'on'):
          target[param] = 'on'
        elif value is False and (param not in target or target[param] != ''):
          target[param] = ''

    for param in SQUID_CONFIG_AUTH_ARGUMENT_SPEC:
      if SQUID_CONFIG_AUTH_ARGUMENT_SPEC[param]['type'] == 'bool':
        _set_param_bool(obj, param)
      else:
        _set_param(obj, param)

    return obj

  def _validate_params(self):
    """ do some extra checks on input parameters """
    pass

  def run(self, params):
    self.params = params
    self.target_elt = self.root_elt
    self._validate_params()
    self.obj = self._params_to_obj()
    self._add()

  @staticmethod
  def _get_obj_name():
    return "auth"
  
  @staticmethod
  def fvalue_bool(value):
      """ boolean value formatting function """
      if value is None or value is False or value == 'none' or value != 'on':
          return 'False'

      return 'True'

  def _log_fields(self, before=None):
    values = ''

    if before is None:
      for param in SQUID_CONFIG_AUTH_ARGUMENT_SPEC:
        if SQUID_CONFIG_AUTH_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_cli_field(self.obj, param, fvalue=self.fvalue_bool)
        else:
          values += self.format_cli_field(self.obj, param)
    else:
      for param in SQUID_CONFIG_AUTH_ARGUMENT_SPEC:
        if SQUID_CONFIG_AUTH_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_updated_cli_field(self.obj, self.before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        else:
          values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

    return values

class PFSenseSquidConfigAntivirusModule(PFSenseModuleBase):
  @staticmethod
  def get_argument_spec():
    """ return argument spec """
    return SQUID_CONFIG_ANTIVIRUS_ARGUMENT_SPEC(PFSenseModuleBase)
  
  def __init__(self, module, pfsense=None):
    super(PFSenseSquidConfigAntivirusModule, self).__init__(module, pfsense)
    self.name = "pfsense_squid_config"
    self.obj = dict()
    self.before = None
    self.before_elt = None
    pkgs_elt = self.pfsense.get_element('installedpackages')
    squidantivirus_elt = self.pfsense.get_element('squidantivirus', pkgs_elt, create_node=True)
    self.root_elt = self.pfsense.get_element('config', squidantivirus_elt, create_node=True)

  def _params_to_obj(self):
    """ return a dict from module params """
    params = self.params
    obj = self.pfsense.element_to_dict(self.root_elt)
    self.before = deepcopy(obj)
    self.before_elt = deepcopy(self.root_elt)
    
    def _set_param(target, param):
      if params.get(param) is not None:
        if isinstance(params[param], str):
          if param in base64_params:
            target[param] = base64.b64encode(params[param])
          else:
            target[param] = params[param]
        else:
          if param in base64_params:
            target[param] = base64.b64encode('\n'.join(params[param]).encode()).decode()
          elif param == 'clamav_dbservers':
            target[param] = ';'.join(params[param])
          else:
            target[param] = str(params[param])

    def _set_param_bool(target, param):
      if params.get(param) is not None:
        value = params.get(param)
        if param == 'enable_advanced':
          pass
        elif value is True and (param not in target or target[param] != 'on'):
          target[param] = 'on'
        elif value is False and (param not in target or target[param] != ''):
          target[param] = ''

    for param in SQUID_CONFIG_ANTIVIRUS_ARGUMENT_SPEC:
      if SQUID_CONFIG_ANTIVIRUS_ARGUMENT_SPEC[param]['type'] == 'bool':
        _set_param_bool(obj, param)
      else:
        _set_param(obj, param)

    return obj

  def _validate_params(self):
    """ do some extra checks on input parameters """
    pass

  def run(self, params):
    self.params = params
    self.target_elt = self.root_elt
    self._validate_params()
    self.obj = self._params_to_obj()
    self._add()

  @staticmethod
  def _get_obj_name():
    return "antivirus"
  
  @staticmethod
  def fvalue_bool(value):
      """ boolean value formatting function """
      if value is None or value is False or value == 'none' or value != 'on':
          return 'False'

      return 'True'

  def _log_fields(self, before=None):
    values = ''

    if before is None:
      for param in SQUID_CONFIG_ANTIVIRUS_ARGUMENT_SPEC:
        if SQUID_CONFIG_ANTIVIRUS_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_cli_field(self.obj, param, fvalue=self.fvalue_bool)
        else:
          values += self.format_cli_field(self.obj, param)
    else:
      for param in SQUID_CONFIG_ANTIVIRUS_ARGUMENT_SPEC:
        if SQUID_CONFIG_ANTIVIRUS_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_updated_cli_field(self.obj, before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        else:
          values += self.format_updated_cli_field(self.obj, before, param, add_comma=(values), log_none=False)

    return values

class PFSenseSquidConfigCacheModule(PFSenseModuleBase):
  @staticmethod
  def get_argument_spec():
    """ return argument spec """
    return SQUID_CONFIG_CACHE_ARGUMENT_SPEC(PFSenseModuleBase)
  
  def __init__(self, module, pfsense=None):
    super(PFSenseSquidConfigCacheModule, self).__init__(module, pfsense)
    self.name = "pfsense_squid_config"
    self.obj = dict()
    self.before = None
    self.before_elt = None
    pkgs_elt = self.pfsense.get_element('installedpackages')
    squidcache_elt = self.pfsense.get_element('squidcache', pkgs_elt, create_node=True)
    self.root_elt = self.pfsense.get_element('config', squidcache_elt, create_node=True)

  def _params_to_obj(self):
    """ return a dict from module params """
    params = self.params
    obj = self.pfsense.element_to_dict(self.root_elt)
    self.before = deepcopy(obj)
    self.before_elt = deepcopy(self.root_elt)
    
    def _set_param(target, param):
      if params.get(param) is not None:
        if isinstance(params[param], str):
          target[param] = params[param]
        else:
          target[param] = str(params[param])
    
    def _set_param_list(target, param):
      if params.get(param) is not None:
        if param in base64_params:
          target[param] = base64.b64encode('\n'.join(params[param]).encode()).decode()
        elif param == 'ext_cachemanager':
          target[param] = ';'.join(params[param])

    def _set_param_bool(target, param):
      if params.get(param) is not None:
        value = params.get(param)
        if value is True and (param not in target or target[param] != 'on'):
          target[param] = 'on'
        elif value is False and (param not in target or target[param] != ''):
          target[param] = ''
          
    for param in SQUID_CONFIG_CACHE_ARGUMENT_SPEC:
      if SQUID_CONFIG_CACHE_ARGUMENT_SPEC[param]['type'] == 'bool':
        _set_param_bool(obj, param)
      elif SQUID_CONFIG_CACHE_ARGUMENT_SPEC[param]['type'] == 'list':
        _set_param_list(obj, param)
      else:
        _set_param(obj, param)

    return obj

  def _validate_params(self):
    """ do some extra checks on input parameters """
    pass

  def run(self, params):
    self.params = params
    self.target_elt = self.root_elt
    self._validate_params()
    self.obj = self._params_to_obj()
    self._add()

  @staticmethod
  def _get_obj_name():
    return "cache"

  @staticmethod
  def fvalue_bool(value):
      """ boolean value formatting function """
      if value is None or value is False or value == 'none' or value != 'on':
          return 'False'

      return 'True'

  def _log_fields(self, before=None):
    values = ''

    if before is None:
      for param in SQUID_CONFIG_CACHE_ARGUMENT_SPEC:
        if SQUID_CONFIG_CACHE_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_cli_field(self.obj, param, fvalue=self.fvalue_bool)
        else:
          values += self.format_cli_field(self.obj, param)
    else:
      for param in SQUID_CONFIG_CACHE_ARGUMENT_SPEC:
        if SQUID_CONFIG_CACHE_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_updated_cli_field(self.obj, before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        else:
          values += self.format_updated_cli_field(self.obj, before, param, add_comma=(values), log_none=False)

    return values

class PFSenseSquidConfigGeneralModule(PFSenseModuleBase):
  @staticmethod
  def get_argument_spec():
    """ return argument spec """
    return SQUID_CONFIG_GENERAL_ARGUMENT_SPEC(PFSenseModuleBase)

  def __init__(self, module, pfsense=None):
    super(PFSenseSquidConfigGeneralModule, self).__init__(module, pfsense)
    self.name = "pfsense_squid_config"
    self.obj = dict()
    self.before = None
    self.before_elt = None
    pkgs_elt = self.pfsense.get_element('installedpackages')
    squid_elt = self.pfsense.get_element('squid', pkgs_elt, create_node=True)
    self.root_elt = self.pfsense.get_element('config', squid_elt, create_node=True)

  def _params_to_obj(self):
    """ return a dict from module params """
    params = self.params
    obj = self.pfsense.element_to_dict(self.root_elt)
    self.before = deepcopy(obj)
    self.before_elt = deepcopy(self.root_elt)
    
    def _set_param(target, param):
      if params.get(param) is not None:
        if isinstance(params[param], str):
          if param in base64_params:
            target[param] = base64.b64encode(params[param])
          elif param in cert_params:
            ca_elt = self.pfsense.find_ca_elt(params[param])
            target[param] = ca_elt.find('refid').text
          else:
            target[param] = params[param]
        else:
          if param in base64_params:
            target[param] = base64.b64encode('\n'.join(params[param]).encode()).decode()
          else:
            target[param] = str(params[param])

    def _set_param_bool(target, param):
      if params.get(param) is not None:
        value = params.get(param)
        if value is True and (param not in target or target[param] != 'on'):
          target[param] = 'on'
        elif value is False and (param not in target or target[param] != ''):
          target[param] = ''

    def _set_param_list(target, param):
      if params.get(param) is not None:
        if param in base64_params:
          target[param] = base64.b64encode('\n'.join(params[param]).encode()).decode()
        elif param in ['active_interface', 'transparent_active_interface', 'ssl_active_interface', 'interception_adapt', 'interception_checks', 'google_accounts']:
          target[param] = ','.join(params[param])
        elif param in ['addtl_ports', 'addtl_sslports']:
          target[param] = ' '.join(params[param])
        elif param in ['dns_nameservers', 'defined_ip_proxy_off', 'defined_ip_proxy_off_dest']:
          target[param] = ';'.join(params[param])

    for param in SQUID_CONFIG_GENERAL_ARGUMENT_SPEC:
      if SQUID_CONFIG_GENERAL_ARGUMENT_SPEC[param]['type'] == 'bool':
        _set_param_bool(obj, param)
      elif SQUID_CONFIG_GENERAL_ARGUMENT_SPEC[param]['type'] == 'list':
        _set_param_list(obj, param)
      else:
        _set_param(obj, param)

    return obj

  def _validate_params(self):
    """ do some extra checks on input parameters """
    pass

  def run(self, params):
    self.params = params
    self.target_elt = self.root_elt
    self._validate_params()
    self.obj = self._params_to_obj()
    self._add()

  @staticmethod
  def _get_obj_name():
    return "general"
  
  @staticmethod
  def fvalue_bool(value):
      """ boolean value formatting function """
      if value is None or value is False or value == 'none' or value != 'on':
          return 'False'

      return 'True'

  def _log_fields(self, before=None):
    values = ''

    if before is None:
      for param in SQUID_CONFIG_GENERAL_ARGUMENT_SPEC:
        if SQUID_CONFIG_GENERAL_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_cli_field(self.obj, param, fvalue=self.fvalue_bool)
        else:
          values += self.format_cli_field(self.obj, param)
    else:
      for param in SQUID_CONFIG_GENERAL_ARGUMENT_SPEC:
        if SQUID_CONFIG_GENERAL_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_updated_cli_field(self.obj, self.before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        else:
          values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

    return values

class PFSenseSquidConfigNacModule(PFSenseModuleBase):
  @staticmethod
  def _get_obj_name():
    return "nac"

  def __init__(self, module, pfsense=None):
    super(PFSenseSquidConfigNacModule, self).__init__(module, pfsense)
    self.name = "pfsense_squid_config"
    self.obj = dict()
    self.before = None
    self.before_elt = None
    pkgs_elt = self.pfsense.get_element('installedpackages')
    squidnac_elt = self.pfsense.get_element('squidnac', pkgs_elt, create_node=True)
    self.root_elt = self.pfsense.get_element('config', squidnac_elt, create_node=True)

  def _params_to_obj(self):
    """ return a dict from module params """
    params = self.params
    obj = self.pfsense.element_to_dict(self.root_elt)
    self.before = deepcopy(obj)
    self.before_elt = deepcopy(self.root_elt)

    def _set_param(target, param):
      if params.get(param) is not None:
        if isinstance(params[param], str):
          if param in base64_params:
            target[param] = base64.b64encode(params[param])
          else:
            target[param] = params[param]
        else:
          if param in base64_params:
            target[param] = base64.b64encode('\n'.join(params[param]).encode()).decode()
          else:
            target[param] = str(params[param])

    for param in SQUID_CONFIG_NAC_ARGUMENT_SPEC:
      _set_param(obj, param)

    return obj

  def _validate_params(self):
    """ do some extra checks on input parameters """
    pass

  def run(self, params):
    self.params = params
    self.target_elt = self.root_elt
    self._validate_params()
    self.obj = self._params_to_obj()
    self._add()

  def _log_fields(self, before=None):
    values = ''

    if before is None:
      for param in SQUID_CONFIG_NAC_ARGUMENT_SPEC:
        values += self.format_cli_field(self.obj, param)
    else:
      for param in SQUID_CONFIG_NAC_ARGUMENT_SPEC:
        values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

    return values

class PFSenseSquidConfigRemoteModule(PFSenseModuleBase):
  @staticmethod
  def get_argument_spec():
    """ return argument spec """
    return SQUID_CONFIG_REMOTE_ARGUMENT_SPEC(PFSenseModuleBase)
  
  def __init__(self, module, pfsense=None):
    super(PFSenseSquidConfigRemoteModule, self).__init__(module, pfsense)
    self.name = "pfsense_squid_config"
    self.obj = dict()
    self.before = None
    self.before_elt = None
    pkgs_elt = self.pfsense.get_element('installedpackages', create_node=True)
    self.root_elt = self.pfsense.get_element('squidremote', pkgs_elt, create_node=True)

  def _params_to_obj(self):
    """ return a dict from module params """
    params = self.params
    obj = dict()
    obj['proxyname'] = params['proxyname']
    obj['proxyaddr'] = params['proxyaddr']
    if params['state'] == 'present':
      if params['enable']:
        obj['enable'] = 'on'
      obj['proxyport'] = str(params['proxyport'])
      obj['allowmiss'] = ','.join(params['allowmiss'])
      obj['hierarchy'] = params['hierarchy']
      obj['peermethod'] = params['peermethod']
      obj['weight'] = str(params['weight'])
      obj['basetime'] = str(params['basetime'])
      obj['ttl'] = str(params['ttl'])
      if params['nodelay']:
        obj['nodelay'] = 'on'
      obj['icpport'] = str(params['icpport'])
      obj['icpoptions'] = params['icpoptions']
      obj['username'] = params['username']
      obj['password'] = params['password']
      obj['authoption'] = params['authoption']

    return obj

  def _validate_params(self):
    """ do some extra checks on input parameters """
    pass

  def _create_target(self):
    """ create the XML target_elt """
    config_elt = self.pfsense.new_element('config')
    return config_elt

  def _find_target(self):
    """ find the XML target_elt """
    for config_elt in self.root_elt:
      if config_elt.tag != 'config':
        continue
      proxyname_elt = config_elt.find('proxyname')
      proxyaddr_elt = config_elt.find('proxyaddr')
      if (proxyname_elt is not None and proxyname_elt.text == self.obj['proxyname']) and (proxyaddr_elt is not None and proxyaddr_elt.text == self.obj['proxyaddr']):
        return config_elt

    return None

  @staticmethod
  def _get_obj_name():
    return "remote"
  
  @staticmethod
  def fvalue_bool(value):
      """ boolean value formatting function """
      if value is None or value is False or value == 'none' or value != 'on':
          return 'False'

      return 'True'

  def _log_fields(self, before=None):
    values = ''

    if before is None:
      for param in SQUID_CONFIG_REMOTE_ARGUMENT_SPEC:
        if SQUID_CONFIG_REMOTE_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_cli_field(self.obj, param, fvalue=self.fvalue_bool)
        else:
          values += self.format_cli_field(self.obj, param)
    else:
      for param in SQUID_CONFIG_REMOTE_ARGUMENT_SPEC:
        if SQUID_CONFIG_REMOTE_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_updated_cli_field(self.obj, before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        else:
          values += self.format_updated_cli_field(self.obj, before, param, add_comma=(values), log_none=False)

    return values

class PFSenseSquidConfigSyncModule(PFSenseModuleBase):
  @staticmethod
  def _get_obj_name():
    return "sync"

  def __init__(self, module, pfsense=None):
    super(PFSenseSquidConfigSyncModule, self).__init__(module, pfsense)
    self.name = "pfsense_squid_config"
    self.obj = dict()
    self.before = None
    self.before_elt = None

    pkgs_elt = self.pfsense.get_element('installedpackages', create_node=True)
    squidsync_elt = self.pfsense.get_element('squidsync', pkgs_elt, create_node=True)
    self.root_elt = self.pfsense.get_element('config', squidsync_elt, create_node=True)

  def _params_to_obj(self):
    """ return a dict from module params """
    obj = self.pfsense.element_to_dict(self.root_elt)
    self.before = deepcopy(obj)
    self.before_elt = deepcopy(self.root_elt)

    def _set_param_list(target, params, param):
      if params.get(param) is not None:
        if param == 'synctargets':
          synctargets = []
          for entry in params.get(param):
            synctarget = dict()
            for subparam in SQUID_CONFIG_SYNC_TARGET_ARGUMENT_SPEC:
              if entry.get(subparam) is not None:
                if SQUID_CONFIG_SYNC_TARGET_ARGUMENT_SPEC[subparam]['type'] == 'bool':
                  _set_param_bool(synctarget, entry, subparam)
                else:
                  _set_param(synctarget, entry, subparam)
            synctargets.append(synctarget)
          target['row'] = synctargets

    def _set_param_bool(target, params, param):
      if params.get(param) is not None:
        value = params.get(param)
        if value is True and param not in target:
          target[param] = 'ON'
        elif value is False and param in target:
          del target[param]

    def _set_param(target, params, param):
      if params.get(param) is not None:
        if isinstance(params[param], str):
          target[param] = params[param]
        else:
          target[param] = str(params[param])

    for param in SQUID_CONFIG_SYNC_ARGUMENT_SPEC:
      if SQUID_CONFIG_SYNC_ARGUMENT_SPEC[param]['type'] == 'bool':
        _set_param_bool(obj, self.params, param)
      elif SQUID_CONFIG_SYNC_ARGUMENT_SPEC[param]['type'] == 'list':
        _set_param_list(obj, self.params, param)
      else:
        _set_param(obj, self.params, param)

    return obj

  def _validate_params(self):
    """ do some extra checks on input parameters """
    pass

  def run(self, params):
    self.params = params
    self.target_elt = self.root_elt
    self._validate_params()
    self.obj = self._params_to_obj()
    self._add()

  @staticmethod
  def fvalue_bool(value):
      """ boolean value formatting function """
      if value is None or value is False or value == 'none' or value != 'ON':
          return 'False'

      return 'True'

  def _log_fields(self, before=None):
    values = ''

    if before is None:
      for param in SQUID_CONFIG_SYNC_ARGUMENT_SPEC:
        values += self.format_cli_field(self.obj, param)
    else:
      for param in SQUID_CONFIG_SYNC_ARGUMENT_SPEC:
        values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

    return values

class PFSenseSquidConfigTrafficModule(PFSenseModuleBase):
  @staticmethod
  def get_argument_spec():
    """ return argument spec """
    return SQUID_CONFIG_TRAFFIC_ARGUMENT_SPEC(PFSenseModuleBase)
  
  def __init__(self, module, pfsense=None):
    super(PFSenseSquidConfigTrafficModule, self).__init__(module, pfsense)
    self.name = "pfsense_squid_config"
    self.obj = dict()
    self.before = None
    self.before_elt = None

    pkgs_elt = self.pfsense.get_element('installedpackages', create_node=True)
    squidtraffic_elt = self.pfsense.get_element('squidtraffic', pkgs_elt, create_node=True)
    self.root_elt = self.pfsense.get_element('config', squidtraffic_elt, create_node=True)

  def _params_to_obj(self):
    """ return a dict from module params """
    params = self.params
    obj = self.pfsense.element_to_dict(self.root_elt)
    self.before = deepcopy(obj)
    self.before_elt = deepcopy(self.root_elt)
    
    def _set_param(target, param):
      if params.get(param) is not None:
        if isinstance(params[param], str):
          target[param] = params[param]
        else:
          target[param] = str(params[param])
    
    def _set_param_list(target, param):
      if params.get(param) is not None:
        if param in base64_params:
          target[param] = base64.b64encode('\n'.join(params[param]).encode()).decode()
        elif param == 'ext_cachemanager':
          target[param] = ';'.join(params[param])

    def _set_param_bool(target, param):
      if params.get(param) is not None:
        value = params.get(param)
        if value is True and (param not in target or target[param] != 'on'):
          target[param] = 'on'
        elif value is False and (param not in target or target[param] != ''):
          target[param] = ''
          
    for param in SQUID_CONFIG_TRAFFIC_ARGUMENT_SPEC:
      if SQUID_CONFIG_TRAFFIC_ARGUMENT_SPEC[param]['type'] == 'bool':
        _set_param_bool(obj, param)
      elif SQUID_CONFIG_TRAFFIC_ARGUMENT_SPEC[param]['type'] == 'list':
        _set_param_list(obj, param)
      else:
        _set_param(obj, param)

    return obj

  def _validate_params(self):
    """ do some extra checks on input parameters """
    pass

  def run(self, params):
    self.params = params
    self.target_elt = self.root_elt
    self._validate_params()
    self.obj = self._params_to_obj()
    self._add()

  @staticmethod
  def _get_obj_name():
    return "traffic"

  @staticmethod
  def fvalue_bool(value):
      """ boolean value formatting function """
      if value is None or value is False or value == 'none' or value != 'on':
          return 'False'

      return 'True'

  def _log_fields(self, before=None):
    values = ''

    if before is None:
      for param in SQUID_CONFIG_TRAFFIC_ARGUMENT_SPEC:
        if SQUID_CONFIG_TRAFFIC_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_cli_field(self.obj, param, fvalue=self.fvalue_bool)
        else:
          values += self.format_cli_field(self.obj, param)
    else:
      for param in SQUID_CONFIG_TRAFFIC_ARGUMENT_SPEC:
        if SQUID_CONFIG_TRAFFIC_ARGUMENT_SPEC[param]['type'] == 'bool':
          values += self.format_updated_cli_field(self.obj, before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        else:
          values += self.format_updated_cli_field(self.obj, before, param, add_comma=(values), log_none=False)

    return values
class PFSenseSquidConfigUsersModule(PFSenseModuleBase):
  @staticmethod
  def get_argument_spec():
    """ return argument spec """
    return SQUID_CONFIG_USER_ARGUMENT_SPEC(PFSenseModuleBase)

  def __init__(self, module, pfsense=None):
    super(PFSenseSquidConfigUsersModule, self).__init__(module, pfsense)
    self.name = "pfsense_squid_config"
    self.obj = dict()
    pkgs_elt = self.pfsense.get_element('installedpackages', create_node=True)
    self.root_elt = self.pfsense.get_element('squidusers', pkgs_elt, create_node=True)

    self.users = None

  def _params_to_obj(self):
    """ return a dict from module params """
    obj = dict()
    obj['username'] = self.params['username']
    if self.params['state'] == 'present':
      obj['password'] = self.params['password']
      obj['description'] = self.params['description']

    return obj

  def _validate_params(self):
    """ do some extra checks on input parameters """
    pass
  
  def _create_target(self):
    """ create the XML target_elt """
    config_elt = self.pfsense.new_element('config')
    return config_elt

  def _find_target(self):
    """ find the XML target_elt """
    for config_elt in self.root_elt:
      if config_elt.tag != 'config':
        continue
      username_elt = config_elt.find('username')
      if username_elt is not None and username_elt.text == self.obj['username']:
        return config_elt

    return None

  @staticmethod
  def _get_obj_name():
    return "users"

  def _log_fields(self, before=None):
    values = ''

    if before is None:
      for param in SQUID_CONFIG_USER_ARGUMENT_SPEC:
        values += self.format_cli_field(self.obj, param)
    else:
      for param in SQUID_CONFIG_USER_ARGUMENT_SPEC:
        values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

    return values

class PFSenseSquidModule(object):
  """ module managing pfsense squid http proxy settings """

  def __init__(self, module):
    self.module = module
    self.pfsense = PFSenseModule(module)
    self.pfsense_squid_auth = PFSenseSquidConfigAuthModule(module, self.pfsense)
    self.pfsense_squid_antivirus = PFSenseSquidConfigAntivirusModule(module, self.pfsense)
    self.pfsense_squid_cache = PFSenseSquidConfigCacheModule(module, self.pfsense)
    self.pfsense_squid_general = PFSenseSquidConfigGeneralModule(module, self.pfsense)
    self.pfsense_squid_nac = PFSenseSquidConfigNacModule(module, self.pfsense)
    self.pfsense_squid_remotes = PFSenseSquidConfigRemoteModule(module, self.pfsense)
    self.pfsense_squid_sync = PFSenseSquidConfigSyncModule(module, self.pfsense)
    self.pfsense_squid_traffic = PFSenseSquidConfigTrafficModule(module, self.pfsense)
    self.pfsense_squid_users = PFSenseSquidConfigUsersModule(module, self.pfsense)

  def _update(self):
    run = False

    cmd = '''require_once("filter.inc");
    require_once("squid.inc");
    squid_resync();
    '''

    if self.pfsense_squid_auth.result['changed']:
      run = True
    elif self.pfsense_squid_antivirus.result['changed']:
      run = True
    elif self.pfsense_squid_cache.result['changed']:
      run = True
    elif self.pfsense_squid_general.result['changed']:
      run = True
    elif self.pfsense_squid_nac.result['changed']:
      run = True
    elif self.pfsense_squid_remotes.result['changed']:
      run = True
    elif self.pfsense_squid_sync.result['changed']:
      run = True
    elif self.pfsense_squid_traffic.result['changed']:
      run = True
    elif self.pfsense_squid_users.result['changed']:
      run = True

    if run:
      return self.pfsense.phpshell(cmd)

    return ('', '', '')

  def run_auth(self):
    want = self.module.params['auth']
    if want is not None:
      self.pfsense_squid_auth.run(want)
  
  def run_antivirus(self):
    want = self.module.params['antivirus']
    if want is not None:
      self.pfsense_squid_antivirus.run(want)
  
  def run_cache(self):
    want = self.module.params['cache']
    if want is not None:
      self.pfsense_squid_cache.run(want)

  def run_general(self):
    want = self.module.params['general']
    if want is not None:
      self.pfsense_squid_general.run(want)
  
  def run_nac(self):
    want = self.module.params['nac']
    if want is not None:
      self.pfsense_squid_nac.run(want)
  
  @staticmethod
  def want_remote(config_elt, remotes):
    """ return True if we want to keep config_elt """
    proxyname = config_elt.find('proxyname').text
    proxyaddr = config_elt.find('proxyaddr').text

    for remote in remotes:
      if remote['state'] == 'absent':
        continue
      if remote['proxyname'] == proxyname and remote['proxyaddr'] == proxyaddr:
        return True
    return False
  
  def run_remotes(self):
    want = self.module.params['remotes']
    if want is None:
      return

    for param in want:
      self.pfsense_squid_remotes.run(param)
    
    if self.module.params['purge_remotes']:
      todel = []
      for config_elt in self.pfsense_squid_remotes.root_elt:
        if not self.want_remote(config_elt, want):
          params = {}
          params['state'] = 'absent'
          params['proxyaddr'] = config_elt.find('proxyaddr').text
          params['proxyname'] = config_elt.find('proxyname').text
          todel.append(params)

      for params in todel:
        self.pfsense_squid_remotes.run(params)
  
  def run_sync(self):
    want = self.module.params['sync']
    if want is not None:
      self.pfsense_squid_sync.run(want)
  
  def run_traffic(self):
    want = self.module.params['traffic']
    if want is not None:
      self.pfsense_squid_traffic.run(want)
        
  @staticmethod
  def want_user(config_elt, users):
    """ return True if we want to keep config_elt """
    username = config_elt.find('username').text

    for user in users:
      if user['state'] == 'absent':
        continue
      if user['username'] == username:
        return True
    return False

  def run_users(self):
    want = self.module.params['users']
    if want is None:
      return

    for param in want:
      self.pfsense_squid_users.run(param)

    if self.module.params['purge_users']:
      todel = []
      for config_elt in self.pfsense_squid_users.root_elt:
        if not self.want_user(config_elt, want):
          params = {}
          params['state'] = 'absent'
          params['username'] = config_elt.find('username').text
          todel.append(params)

      for params in todel:
        self.pfsense_squid_users.run(params)

  def commit_changes(self):
    stdout = ''
    stderr = ''
    changed = (
      self.pfsense_squid_auth.result['changed'] or
      self.pfsense_squid_antivirus.result['changed'] or
      self.pfsense_squid_cache.result['changed'] or
      self.pfsense_squid_general.result['changed'] or
      self.pfsense_squid_nac.result['changed'] or
      self.pfsense_squid_remotes.result['changed'] or
      self.pfsense_squid_sync.result['changed'] or
      self.pfsense_squid_traffic.result['changed'] or
      self.pfsense_squid_users.result['changed']
    )
    
    if changed and not self.module.check_mode:
      self.pfsense.write_config(descr='squid config')
      (dummy, stdout, stderr) = self._update()

    result = {}
    result['result_auth'] = self.pfsense_squid_auth.result['commands']
    result['result_antivirus'] = self.pfsense_squid_antivirus.result['commands']
    result['result_cache'] = self.pfsense_squid_cache.result['commands']
    result['result_general'] = self.pfsense_squid_general.result['commands']
    result['result_nac'] = self.pfsense_squid_nac.result['commands']
    result['result_remotes'] = self.pfsense_squid_remotes.result['commands']
    result['result_sync'] = self.pfsense_squid_sync.result['commands']
    result['result_traffic'] = self.pfsense_squid_traffic.result['commands']
    result['result_users'] = self.pfsense_squid_users.result['commands']

    result['diff_auth'] = self.pfsense_squid_auth.diff
    result['diff_antivirus'] = self.pfsense_squid_antivirus.diff
    result['diff_cache'] = self.pfsense_squid_cache.diff
    result['diff_general'] = self.pfsense_squid_general.diff
    result['diff_nac'] = self.pfsense_squid_nac.diff
    result['diff_remotes'] = self.pfsense_squid_remotes.diff
    result['diff_sync'] = self.pfsense_squid_sync.diff
    result['diff_traffic'] = self.pfsense_squid_traffic.diff
    result['diff_users'] = self.pfsense_squid_users.diff

    result['changed'] = changed
    result['stdout'] = stdout
    result['stderr'] = stderr
    self.module.exit_json(**result)

def main():
  module = AnsibleModule(
    argument_spec=dict(
      auth=dict(type='dict', options=SQUID_CONFIG_AUTH_ARGUMENT_SPEC),
      antivirus=dict(type='dict', options=SQUID_CONFIG_ANTIVIRUS_ARGUMENT_SPEC),
      cache=dict(type='dict', options=SQUID_CONFIG_CACHE_ARGUMENT_SPEC),
      general=dict(type='dict', options=SQUID_CONFIG_GENERAL_ARGUMENT_SPEC),
      nac=dict(type='dict', options=SQUID_CONFIG_NAC_ARGUMENT_SPEC),
      remotes=dict(type='list', elements='dict', options=SQUID_CONFIG_REMOTE_ARGUMENT_SPEC),
      sync=dict(type='dict', options=SQUID_CONFIG_SYNC_ARGUMENT_SPEC),
      traffic=dict(type='list', elements='dict', options=SQUID_CONFIG_TRAFFIC_ARGUMENT_SPEC),
      users=dict(type='list', elements='dict', options=SQUID_CONFIG_USER_ARGUMENT_SPEC),
      purge_remotes=dict(type='bool', default=False),
      purge_users=dict(type='bool', default=False),
    ),
    supports_check_mode=True)

  pfmodule = PFSenseSquidModule(module)
  pfmodule.run_auth()
  pfmodule.run_antivirus()
  pfmodule.run_cache()
  pfmodule.run_general()
  pfmodule.run_nac()
  pfmodule.run_remotes()
  pfmodule.run_sync()
  pfmodule.run_traffic()
  pfmodule.run_users()

  pfmodule.commit_changes()


if __name__ == '__main__':
  main()
