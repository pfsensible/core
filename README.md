# ansible-pfsense / pfsensible.core

This is a set of modules to allow you to configure pfSense firewalls with ansible.

### NOTE: Changes with pfsensible.core 0.4.0

With pfsensible.core 0.4.0 we have stopped stripping the pfsense_ prefix from the module names.  This caused conflicts with other
modules (like the ansible core 'setup' module).  You can use the ['collections'](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html#simplifying-module-names-with-the-collections-keyword)
keyword in your playbooks and roles to simplify the module names instead.

## Installation using ansible galaxy

Ansible Galaxy (as of version 2.9) now has an option for collections.  A collection is a distribution
format for delivering all type of Ansible content (not just roles as it was before).  To install:

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
  - name: "Install packages"
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
pre-change bytes in `/cf/conf/config.xml.ansible.bak` with mode `0600`. This is one
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

The temporary transport document is parsed and reformatted by PHP before it can
replace the live file. The formatted document must parse back to the same native
configuration array and match the intended Python values and structure. Comparison
ignores formatting whitespace and order between different named fields, matching
PHP associative arrays. Entries sharing a tag retain their order: firewall/NAT
rules and lists of VPN servers or clients cannot be silently reordered. For
example, appending a new OpenVPN server after existing clients is accepted when
PHP groups it with the other server entries without changing either list's order.
A mismatch aborts the write and reports `config_mismatch` with the first field's
indexed XML path and a reason, without including configuration values. The final
native bytes are
synced before replacement and used for subsequent conflict detection. Formatting
does not run interface assignment, gateway creation, CARP changes, or apply hooks.

Run the standalone regression suite from the collection directory:

```sh
python3 -m unittest discover -s tests/unit/plugins/module_utils -v
```

The tests cover stale snapshots, native lock contention, failed backup/sync/rename,
invalid XML, metadata preservation, cache failures, and package/text round trips.
Native formatting and integration tests run when PHP with its XML extension is
installed and `PFSENSE_XMLPARSE_INC` points to a matching pfSense
`src/etc/inc/xmlparse.inc` (or `/etc/inc/xmlparse.inc` on a test firewall). With
these variables set, filesystem safety tests also run the real native serializer:

```sh
PFSENSE_XMLPARSE_INC=/path/to/pfsense/src/etc/inc/xmlparse.inc \
  python3 -m unittest discover -s tests/unit/plugins/module_utils -v
```

Set `PFSENSE_PHP_BINARY` to use a specific PHP executable or wrapper. Without a
configured PHP runtime, formatting-specific tests are skipped; the other tests
exercise filesystem safety with a stubbed native command.

GitHub Actions runs this suite with PHP and its XML extension in the
`Native pfSense configuration tests` job. It downloads `xmlparse.inc` from a
pinned upstream pfSense revision, checks that the required PHP functions are
available, and enables all native serializer tests. Update
`PFSENSE_XMLPARSE_REVISION` in `.github/workflows/main.yml` to test a newer parser.

Test a full apply on a lab firewall running the deployed pfSense/package versions
before production rollout. The suite uses synthetic configuration and does not
connect to a firewall.

## Modules
The following modules are currently available:

* [pfsense_alias](https://github.com/pfsensible/core/wiki/pfsense_alias) for aliases
* [pfsense_authserver_ldap](https://github.com/pfsensible/core/wiki/pfsense_authserver_ldap) for LDAP authentication servers
* [pfsense_authserver_radius](https://github.com/pfsensible/core/wiki/pfsense_authserver_radius) for RADIUS authentication servers
* [pfsense_ca](https://github.com/pfsensible/core/wiki/pfsense_ca) for Certificate Authorities
* [pfsense_cert](https://github.com/pfsensible/core/wiki/pfsense_cert) for Certificates
* [pfsense_default_gateway](https://github.com/pfsensible/core/wiki/pfsense_default_gateway) for setting the default gateways
* [pfsense_dhcp_static](https://github.com/pfsensible/core/wiki/pfsense_dhcp_static) for static DHCP entries
* [pfsense_dns_resolver](https://github.com/pfsensible/core/wiki/pfsense_dns_resolver) for DNS resolver (unbound) settings
* [pfsense_gateway](https://github.com/pfsensible/core/wiki/pfsense_gateway) for routing gateways
* [pfsense_group](https://github.com/pfsensible/core/wiki/pfsense_group) for user groups
* [pfsense_interface](https://github.com/pfsensible/core/wiki/pfsense_interface) for interfaces
* [pfsense_interface_group](https://github.com/pfsensible/core/wiki/pfsense_interface_group) for interface groups
* [pfsense_ipsec](https://github.com/pfsensible/core/wiki/pfsense_ipsec) for IPsec tunnels and phase 1 options
* [pfsense_ipsec_proposal](https://github.com/pfsensible/core/wiki/pfsense_ipsec_proposal) for IPsec proposals
* [pfsense_ipsec_p2](https://github.com/pfsensible/core/wiki/pfsense_ipsec_p2) for IPsec tunnels phase 2 options
* [pfsense_log_settings](https://github.com/pfsensible/core/wiki/pfsense_log_settings) for logging settings
* [pfsense_openvpn_client](https://github.com/pfsensible/core/wiki/pfsense_openvpn_client) for OpenVPN client configuration
* [pfsense_openvpn_override](https://github.com/pfsensible/core/wiki/pfsense_openvpn_override) for OpenVPN override configuration
* [pfsense_openvpn_server](https://github.com/pfsensible/core/wiki/pfsense_openvpn_server) for OpenVPN server configuration
* [pfsense_nat_outbound](https://github.com/pfsensible/core/wiki/pfsense_nat_outbound) for outbound NAT (SNAT) rules
* [pfsense_nat_port_forward](https://github.com/pfsensible/core/wiki/pfsense_nat_port_forward) for port forwarding NAT (DNAT) rules
* [pfsense_rewrite_config](https://github.com/pfsensible/core/wiki/pfsense_rewrite_config) to rewrite config.xml
* [pfsense_route](https://github.com/pfsensible/core/wiki/pfsense_route) for routes
* [pfsense_rule](https://github.com/pfsensible/core/wiki/pfsense_rule) for firewall rules
* [pfsense_rule_separator](https://github.com/pfsensible/core/wiki/pfsense_rule_separator) for firewall rule separators
* [pfsense_setup](https://github.com/pfsensible/core/wiki/pfsense_setup) for general setup
* [pfsense_user](https://github.com/pfsensible/core/wiki/pfsense_user) for users
* [pfsense_vlan](https://github.com/pfsensible/core/wiki/pfsense_vlan) for VLANs

## Bulk modules
These modules allow you to make important changes at once and, using the purge parameters, to keep the targets configuration strictly synchronized with your playbooks:

* [pfsense_aggregate](https://github.com/pfsensible/core/wiki/pfsense_aggregate) for firewall aliases, rules, and rule separators, plus interfaces and VLANs
* [pfsense_ipsec_aggregate](https://github.com/pfsensible/core/wiki/pfsense_ipsec_aggregate) for IPsec tunnels, phases 1, phases 2 and proposals

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

## Operation

Modules in the collection work by editing `/cf/conf/config.xml` using xml.etree.ElementTree, then
calling the appropriate PHP update function via the pfSense PHP developer shell.

Some formatting is lost, and CDATA items are converted to normal entries,
but so far no problems with that have been noted.

## License

GPLv3.0 or later
