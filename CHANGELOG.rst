=============================
pfSensible.Core Release Notes
=============================

.. contents:: Topics

v0.7.1
======

Minor Changes
-------------

- pfsense_ipsec_p2/proposal - Add missing new DH Groups 31, 32 support in ipsec vpn (https://github.com/pfsensible/core/issues/183)
- pfsense_log_settings - add nologlinklocal4, nologsnort2c, and logconfigchanges parameters (https://github.com/pfsensible/core/pull/199).
- pfsense_user - add disabled parameter (https://github.com/pfsensible/core/pull/208).

Bugfixes
--------

- pfsense_aggregate - fix argument_spec handling for aggregated modules that broke aggregated_nat_outbounds (https://github.com/pfsensible/core/issues/201).
- pfsense_authserver_ldap - Call set_pam_auth() if needed to update system config.
- pfsense_authserver_ldap - Fix disabling ldap_allow_unauthenticated (https://github.com/pfsensible/core/issues/139).
- pfsense_ca - Better validation for name, lifetime, and dn_* parameters (https://github.com/pfsensible/core/pull/142).
- pfsense_dhcp_server - Describe denyunknown options and allow disabling it via `disabled` (https://github.com/pfsensible/core/issues/203).
- pfsense_dns_resolver - Add ability to specify Virtual IPs for interfaces (https://github.com/pfsensible/core/issues/136).
- pfsense_dns_resolver - Fix configuration without domainoverrides set (https://github.com/pfsensible/core/issues/206).
- pfsense_dns_resolver - Fix forward_tls_upstream handling in domainoverrides (https://github.com/pfsensible/core/issues/209).
- pfsense_ipsec_p2 - Allow disabling hash algorithms (https://github.com/pfsensible/core/issues/172)
- pfsense_setup - Fix PHP command to update system broken in 0.7.0 (https://github.com/pfsensible/core/pull/210).

v0.7.0
======

Release Summary
---------------

This is a major refactoring of the ``pfsensible.core`` collection.  The goal
was to support easier creation of new modules via the ``pfsensible-generate-module``
script. PFSenseModuleBase was expanded to handle more common functions via
configuration options and callback functions.

Minor Changes
-------------

- pfsense_alias - Add `url` parameter and deprecate using `address` for `urltable` and `urltable_ports` types.
- pfsense_ca - Add ability to create internal CAs. (https://github.com/pfsensible/core/issues/135)
- pfsense_rule - Change `after` to insert after the last match instead of the first.

Breaking Changes / Porting Guide
--------------------------------

- This release is only expected to work with pfSense 2.8.0+ / pfSense Plus 24.11+ due to changes in various lookup_*() functions in pfSense.

Bugfixes
--------

- Use config_get_path() to load configuration in php update commands. Fixes various update commands not working with pfSense 2.8.0 (https://github.com/pfsensible/core/issues/190)
- pfsense_ca / pfsense_cert - Fix validation of base64 encoded keys and certs. (https://github.com/pfsensible/core/issues/174)
- pfsense_ca/pfsense_cert - Restart services affected by updated certificates. (https://github.com/pfsensible/core/issues/191)
- pfsense_cert - Write generated internal certificate into config. (https://github.com/pfsensible/core/issues/186)
- pfsense_dns_resolver - do not always add an empty domainoverrides item. (https://github.com/pfsensible/core/issues/187)
- pfsense_interface - fixes removal of an interface when interface group is empty. (https://github.com/pfsensible/core/issues/182)
- pfsense_interface - fixes removal of an interface with `state: absent`. _remove_all_separators() works when no separator exists for that interface. (https://github.com/pfsensible/core/issues/170)

New Modules
-----------

- pfsensible.core.pfsense_dhcp_server - Manage pfSense DHCP servers
- pfsensible.core.pfsense_phpshell - PHP Shell
- pfsensible.core.pfsense_shellcmd - Manage pfSense shellcmds

v0.6.2
======

Minor Changes
-------------

- added ``auto`` choice for ``myid_type`` and ``peerid_type`` (https://github.com/pfsensible/core/issues/145)
- pfsense_ca - added ``key`` parameter to import CA private key (https://github.com/pfsensible/core/issues/57)
- pfsense_dns_resolver - validate ``domainoverrides.ip`` field
- pfsense_openvpn_client - added ``v4only`` and `v6only`` values for ``create_gw`` (https://github.com/pfsensible/core/issues/133)
- pfsense_openvpn_override - support changed semantics of ``push_reset`` in pfSense Plus 24.11
- pfsense_openvpn_server - no longer sort authmode items
- pfsense_setup - Update language list for pfSense 2.7.1 / pfSense Plus 23.09.
- pfsensible_interface - implemented ``ipv6_type: slaac`` and added the ``slaacusev4iface`` parameter (https://github.com/pfsensible/core/issues/121).
- pfsensible_openvpn_server - Allow ``Local Database`` for ``authmode`` parameter (https://github.com/pfsensible/core/issues/125).

Bugfixes
--------

- made pfsense_dns_resolver hosts idempotent (https://github.com/pfsensible/core/issues/151)
- pfsense - handle "."s prefixing php() output triggered by the presense of /var/run/booting and issue a warning (https://github.com/pfsensible/core/issues/118)
- pfsense_dns_resolver - allow for comma separated list of IP addresses in ``hosts.ip`` (https://github.com/pfsensible/core/discussions/150)
- pfsense_openvpn_client - add ``tls_type`` parameter
- pfsense_openvpn_client/server - apply ``tls`` setting to config (https://github.com/pfsensible/core/issues/132)
- pfsense_user - fixed setting multiple groups for a user (https://github.com/pfsensible/core/issues/130)
- set `global $config;` in phpshell() to find update commands in pfSense Plus 24.11

v0.6.1
======

Minor Changes
-------------

- Bump required ansible version to 2.12.
- Have _get_ansible_param_bool set the value to value_false if the parameter is present and false.
- Refactor pfsense_authserver_ldap and pfsense_authserver_radius.  Should not have any visible impact.
- Ship tests so other pfsensible collections can use them.
- pfsense_ca - allow for disabling `randomserial` and `trust` parameters.
- pfsense_dhcp_static - Add arp_table_static_entry argument (https://github.com/https://github.com/pfsensible/core/issues/109).

Deprecated Features
-------------------

- The pfsensible_haproxy* modules have moved to the `pfsensible.haproxy` collection and will be removed from `pfsensible.core` in version 0.8.0.

v0.6.0
======

Major Changes
-------------

- pfsense_default_gateway - Add module for setting the default gateways
- pfsense_dns_resolver - Add module for DNS resolver (unbound) settings

Minor Changes
-------------

- ipaddress support for pfSense 2.4.4
- pfsense_cert - Support EC certs (https://github.com/pfsensible/core/pull/98)
- pfsense_interface - Always return `ifname` - even on interface creation
- pfsense_interface - Prevent removal if interface is part of an interface group
- pfsense_nat_outbound - Allow for NET:INTERFACE addresses
- pfsense_nat_port_forward - 2.4.5 compatibility
- pfsense_openvpn_server - Do not allow removal of an instance with an interface assignment
- pfsense_rule - Add option to ignore an inexistent queue
- pfsense_rule - Add support for floating 'any' interface rule (https://github.com/pfsensible/core/pull/90)
- plugins/lookup/pfsense - Optimization and ignore queue setting
- tests/plays - Add plays for testing with a live pfSense instance

Bugfixes
--------

- pfsense_aggregate - Fix where a rule with a duplicated name would not be deleted if required
- pfsense_dhcp_static - Allow removing entry with just name (https://github.com/pfsensible/core/issues/69)
- pfsense_dhcp_static - Allow use of display name for netif. Error in case a interface group name is specified (https://github.com/pfsensible/core/issues/79)
- pfsense_interface - Properly shut dwon interface and kill dhclient process when removing interface (https://github.com/pfsensible/core/pull/67)
- pfsense_interface_group - Check that members list is unique
- pfsense_interface_group - Fix creation (https://github.com/pfsensible/core/issues/74)
- pfsense_interface_group - `members` is only required for creation
- pfsense_nat_outbound - Fix boolean values, invert (https://github.com/pfsensible/core/issues/92)
- pfsense_openvpn_client - Fix strictuserdn -> strictusercn option (https://github.com/pfsensible/core/pull/93)
- pfsense_openvpn_client/override/server - Allow network alias and non-strict network address for `tunnel_network`/`tunnel_network6` (https://github.com/pfsensible/core/issues/77)
- pfsense_openvpn_server - Fix use of `generate` with `shared_key` and `tls` (https://github.com/pfsensible/core/issues/81)
- pfsense_setup - No default values - leads to unexpected changes (https://github.com/pfsensible/core/issues/91)
- pfsense_user - Fix setting system group membership (https://github.com/pfsensible/core/issues/70)

New Modules
-----------

- pfsensible.core.pfsense_default_gateway - Manage pfSense default gateway
- pfsensible.core.pfsense_dns_resolver - Manage pfSense DNS resolver (unbound) settings
