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

Python discovery in ansible 2.9 and 2.10 will only detect Python up to version 3.7, ansible 2.11 will detect 3.8.  If Python discovery fails, you can set ansible_python_interpreter in your playbook or hosts vars:

pfSense >= 2.5.2:
```
ansible_python_interpreter: /usr/local/bin/python3.8
```
pfSense >= 2.4.5, < 2.5.2:
```
ansible_python_interpreter: /usr/local/bin/python3.7
```
pfSense < 2.4.5:
```
ansible_python_interpreter: /usr/local/bin/python2.7
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
## Modules
The following modules are currently available:

* [pfsense_alias](https://github.com/pfsensible/core/wiki/pfsense_alias) for aliases
* [pfsense_authserver_ldap](https://github.com/pfsensible/core/wiki/pfsense_authserver_ldap) for LDAP authentication servers
* [pfsense_authserver_radius](https://github.com/pfsensible/core/wiki/pfsense_authserver_radius) for RADIUS authentication servers
* [pfsense_ca](https://github.com/pfsensible/core/wiki/pfsense_ca) for Certificate Authorities
* [pfsense_cert](https://github.com/pfsensible/core/wiki/pfsense_cert) for Certificates
* [pfsense_dhcp_static](https://github.com/pfsensible/core/wiki/pfsense_dhcp_static) for static DHCP entries
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

## Operation

Modules in the collection work by editing `/cf/conf/config.xml` using xml.etree.ElementTree, then
calling the appropriate PHP update function via the pfSense PHP developer shell.

Some formatting is lost, and CDATA items are converted to normal entries,
but so far no problems with that have been noted.

## License

GPLv3.0 or later
