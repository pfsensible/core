# ansible-pfsense / pfsensible.core

This is a set of modules to allow you to configure pfSense firewalls with ansible.

## Installation using ansible galaxy

To install:

```
ansible-galaxy collection install pfsensible.core
```

Optionally, you can specify the path of the collection installation with the `-p` option.

```
ansible-galaxy collection install pfsensible.core -p ./collections
```

Additionally, you can set the `collections_paths` option in your `ansible.cfg` file to automatically designate install locations.

```ini
# ansible.cfg
[defaults]
collections_paths=collections
```

## Configuration

Current versions of ansible should automatically detect the version of Python on the pfSense system.  If Python discovery fails, you can set
ansible_python_interpreter in your playbook or hosts vars, e.g. for pfSense 2.7.2:

```
ansible_python_interpreter: /usr/local/bin/python3.11
```

Modules must run as root in order to make changes to the system.  By default pfSense does not have sudo capability so `become` will not work.  You can install it with:
```
  - name: Install packages
    package:
      name:
        - pfSense-pkg-sudo
      state: present
```
and then configure sudo so that your user has permission to use sudo.

## Configuration write protection

The shared Python writer validates XML, the configuration root/version, and the
continued presence of existing system and interface sections before committing.
It also validates and formats the candidate with the firewall's standalone PHP
XML parser and `dump_xml_config()` serializer, which check pfSense-specific list
tags and duplicate entries. It does not load `config.inc`, recover the live
configuration, or run package hooks during validation and formatting.

Each write acquires pfSense's native `/tmp/config.lock`, checks that the file
still matches the bytes read by the module, and rejects a stale snapshot. A
conflict fails the task without replacing either the configuration or its backup;
rerun the task/play from a fresh read after resolving overlapping writers.
There is a 30-second lock timeout. Do not delete the lock file to release a lock.

Before replacing `/cf/conf/config.xml`, the writer atomically saves the exact
pre-change bytes in `/cf/conf/config.xml.ansible.bak` with mode `0600`. This is a single
rotating pre-change copy, not a configuration history or an independently verified
operational backup. Keep a separate known-good backup before a full playbook run.
The config and backup temporary files are created in the config directory,
flushed, synced, and renamed without a cross-filesystem copy fallback. The live
configuration retains its existing owner, group, and permissions. The directory
is synced, and `/tmp/config.cache` is invalidated while the native lock is held.
Failure to persist the backup aborts the write. A failure after config replacement
is reported with `changed: true` and the backup path, so inspect the firewall
before retrying; automatic rollback could overwrite another writer's changes.

The lock is released before PHP apply hooks run, including hooks that write
configuration themselves. This prevents nested-lock deadlocks. Native or external
writers that read an old snapshot and later write it without conflict detection
can still overwrite newer changes; the Python writer cannot make those scripts
transactional. Avoid overlapping playbooks, GUI saves, HA configuration syncs,
and package update jobs during a full apply. This protection does not invoke
native `write_config()` backup history, AutoConfigBackup, or HA synchronization.

The deployed firewall's native serializer determines the final XML declaration,
indentation, newline, entity spelling, CDATA fields, and explicit empty end tags.
There are no copied CDATA field lists, inferred package rules, or preserved
non-native CDATA markers. For example, native `descr`/`description` and
`ldap_basedn` use escaped CDATA, while `shellcmd`, package `cmd`, URLs, and
`custom_options` use ordinary escaped text on versions with those native rules.
The Python reader decodes XML-escaped CDATA once and does not decode ordinary
XML text a second time, preserving literal entity strings and multiline values.
It detects the installed parser's legacy `html_entity_decode($data)` form and
uses the HTML4 entity names expected by that parser for CDATA (for example,
`&copy;` and `&eacute;`). Modern `ENT_XML1` parsers retain XML-only decoding.
This capability check reads the parser source and does not invoke PHP for no-op
rule checks.

Reading uses a single-pass ElementTree builder rather than constructing a DOM,
serializing it, and parsing the XML again. This avoids repeated full-document
conversion for every task.

The temporary transport document is parsed and reformatted by PHP before it can
replace the live file. The formatted document must parse back to the same native
configuration array. Quotes remain literal inside the transport's CDATA because
older native HTML-entity decoder defaults may not decode apostrophe entities;
this preserves quoted OpenVPN options when an unrelated task saves configuration.
The native serializer still controls quote escaping in the final XML. The result
must also match the intended Python values and structure. Comparison ignores
formatting whitespace and order between different named fields, matching
PHP associative arrays. Entries sharing a tag retain their order: firewall/NAT
rules and lists of VPN servers or clients cannot be silently reordered. For
example, appending a new OpenVPN server after existing clients is accepted when
PHP groups it with the other server entries without changing either list's order.
A mismatch aborts the write and reports `config_mismatch` with the first field's
indexed XML path and a reason, without including configuration values. Native
PHP failures also report `native_validation` with a fixed stage name and exit
code (parser loading, candidate parsing, serialization, temporary-file writing,
formatted parsing, or native round-trip comparison). Raw PHP output is never
returned because it may contain configuration secrets. The final
native bytes are
synced before replacement and used for subsequent conflict detection. Formatting
does not run interface assignment, gateway creation, CARP changes, or apply hooks.

## Appliance integration tests

The [system-test framework](tests/system/README.md) runs actual Ansible modules
against a disposable pfSense VM in QEMU. It checks saved configuration, downloaded
alias caches, and live PF rules and tables, including idempotence, check mode,
runtime repair, and reboot persistence. Configure a prepared appliance image URL
and SHA-256 to enable the GitHub system-test workflow. See the framework guide for
image preparation, virtual NIC configuration, local execution, and current coverage.

## Modules

The following modules are currently available:

* [pfsense_alias](https://github.com/pfsensible/core/wiki/pfsense_alias) for aliases
* [pfsense_alias_info](https://github.com/pfsensible/core/wiki//pfsense_alias_info) to list aliases, their configured contents, and whether they are unused
* [pfsense_authserver_ldap](https://github.com/pfsensible/core/wiki/pfsense_authserver_ldap) for LDAP authentication servers
* [pfsense_authserver_radius](https://github.com/pfsensible/core/wiki/pfsense_authserver_radius) for RADIUS authentication servers
* [pfsense_autoconfigbackup](plugins/modules/pfsense_autoconfigbackup.py) for AutoConfigBackup settings
* [pfsense_ca](https://github.com/pfsensible/core/wiki/pfsense_ca) for Certificate Authorities
* [pfsense_cert](https://github.com/pfsensible/core/wiki/pfsense_cert) for Certificates
* [pfsense_default_gateway](https://github.com/pfsensible/core/wiki/pfsense_default_gateway) for setting the default gateways
* [pfsense_dhcp_ha](https://github.com/pfsensible/core/wiki/pfsense_dhcp_ha) for the high availability of the Kea DHCP server
* [pfsense_dhcp_server](https://github.com/pfsensible/core/wiki/pfsense_dhcp_server) for configuring DHCP server
* [pfsense_dhcp_static](https://github.com/pfsensible/core/wiki/pfsense_dhcp_static) for static DHCP entries
* [pfsense_dhcpv6_server](https://github.com/pfsensible/core/wiki/pfsense_dhcpv6_server) for configuring DHCPv6 servers
* [pfsense_dns_resolver](https://github.com/pfsensible/core/wiki/pfsense_dns_resolver) for DNS resolver (unbound) settings
* [pfsense_gateway](https://github.com/pfsensible/core/wiki/pfsense_gateway) for routing gateways
* [pfsense_gateway_group](https://github.com/pfsensible/core/wiki/pfsense_gateway_group) for gateway groups
* [pfsense_group](https://github.com/pfsensible/core/wiki/pfsense_group) for user groups
* [pfsense_interface](https://github.com/pfsensible/core/wiki/pfsense_interface) for interfaces
* [pfsense_interface_group](https://github.com/pfsensible/core/wiki/pfsense_interface_group) for interface groups
* [pfsense_ipsec](https://github.com/pfsensible/core/wiki/pfsense_ipsec) for IPsec tunnels and phase 1 options
* [pfsense_ipsec_proposal](https://github.com/pfsensible/core/wiki/pfsense_ipsec_proposal) for IPsec proposals
* [pfsense_ipsec_p2](https://github.com/pfsensible/core/wiki/pfsense_ipsec_p2) for IPsec tunnels phase 2 options
* [pfsense_ipsec_settings](plugins/modules/pfsense_ipsec_settings.py) for IPsec advanced settings
* [pfsense_log_settings](https://github.com/pfsensible/core/wiki/pfsense_log_settings) for logging settings
* [pfsense_nat_1to1](plugins/modules/pfsense_nat_1to1.py) for 1:1 NAT rules
* [pfsense_nat_outbound](https://github.com/pfsensible/core/wiki/pfsense_nat_outbound) for outbound NAT (SNAT) rules
* [pfsense_nat_port_forward](https://github.com/pfsensible/core/wiki/pfsense_nat_port_forward) for port forwarding NAT (DNAT) rules
* [pfsense_notification_slack](plugins/modules/pfsense_notification_slack.py) for Slack notification settings
* [pfsense_notification_smtp](plugins/modules/pfsense_notification_smtp.py) for SMTP notification settings
* [pfsense_openvpn_client](https://github.com/pfsensible/core/wiki/pfsense_openvpn_client) for OpenVPN client configuration
* [pfsense_openvpn_override](https://github.com/pfsensible/core/wiki/pfsense_openvpn_override) for OpenVPN override configuration
* [pfsense_openvpn_server](https://github.com/pfsensible/core/wiki/pfsense_openvpn_server) for OpenVPN server configuration
* [pfsense_phpshell](https://github.com/pfsensible/core/wiki/pfsense_phpshell) run commands with php-shell
* [pfsense_rewrite_config](https://github.com/pfsensible/core/wiki/pfsense_rewrite_config) to rewrite config.xml
* [pfsense_route](https://github.com/pfsensible/core/wiki/pfsense_route) for routes
* [pfsense_rule](https://github.com/pfsensible/core/wiki/pfsense_rule) for firewall rules
* [pfsense_rule_separator](https://github.com/pfsensible/core/wiki/pfsense_rule_separator) for firewall rule separators
* [pfsense_setup](https://github.com/pfsensible/core/wiki/pfsense_setup) for general setup
* [pfsense_shellcmd](https://github.com/pfsensible/core/wiki/pfsense_shellcmd) for shellcmd package
* [pfsense_update_settings](https://github.com/pfsensible/core/wiki/pfsense_update_settings) for the update settings
* [pfsense_user](https://github.com/pfsensible/core/wiki/pfsense_user) for users
* [pfsense_virtual_ip_alias](https://github.com/pfsensible/core/wiki/pfsense_virtual_ip_alias) for alias Virtual IPs
* [pfsense_virtual_ip_carp](https://github.com/pfsensible/core/wiki/pfsense_virtual_ip_carp) for CARP Virtual IPs
* [pfsense_virtual_ip_other](https://github.com/pfsensible/core/wiki/pfsense_virtual_ip_other) for other Virtual IPs
* [pfsense_virtual_ip_proxy_arp](https://github.com/pfsensible/core/wiki/pfsense_virtual_ip_proxy_arp) for proxy ARP Virtual IPs
* [pfsense_vlan](https://github.com/pfsensible/core/wiki/pfsense_vlan) for VLANs

## Bulk modules
These modules allow you to make important changes at once and, using the purge parameters, to keep the targets configuration strictly synchronized with your playbooks:

* [pfsense_aggregate](https://github.com/pfsensible/core/wiki/pfsense_aggregate) for firewall aliases, rules, and rule separators, plus interfaces, VLANs and DHCP static mappings
* [pfsense_ipsec_aggregate](https://github.com/pfsensible/core/wiki/pfsense_ipsec_aggregate) for IPsec tunnels, phases 1, phases 2 and proposals
* [pfsense_openvpn_aggregate](plugins/modules/pfsense_openvpn_aggregate.py) for OpenVPN servers, clients and client specific overrides

## Third party modules
These modules allow you to manage installed packages:

* [pfsense_haproxy_backend](https://github.com/pfsensible/core/wiki/pfsense_haproxy_backend) for HAProxy backends
* [pfsense_haproxy_backend_server](https://github.com/pfsensible/core/wiki/pfsense_haproxy_backend_server) for HAProxy backends servers

## [Change Log](https://github.com/pfsensible/core/blob/master/CHANGELOG.rst)

## High-Availability Configuration Syncing
pfsensible modules do not trigger an XMLRPC configuration sync to a secondary system.  But this can be done with the use of a handler as shown:
```
tasks:
  -  name: Make a chage
     pfsensible.core.alias:
       name: an_alias
       state: absent
     become: true
     notify: sync config
handlers:
  - name: sync config
    pfsensible.core.pfsense_rewrite_config:
    become: true
```

## Writing new modules

See [GENERATING_MODULES](https://github.com/pfsensible/core/blob/master/GENERATING_MODULES.md) for instructions on how to use the
pfensible-generate-module script to automate the task writing basic pfsensible modules.

## License

GPLv3.0 or later
