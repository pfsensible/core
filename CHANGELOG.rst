=============================
pfSensible.Core Release Notes
=============================

.. contents:: Topics


v0.6.0
======

Major Changes
-------------

- pfsense_default_gateway - Add module for setting the default gateways (https://github.com/pfsensible/core/pull/99)
- pfsense_dns_resolver - Add module for DNS resolver (unbound) settings (https://github.com/pfsensible/core/pull/76)

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
