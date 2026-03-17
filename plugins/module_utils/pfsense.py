# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import sys
if sys.version_info >= (3, 4):
    import html
try:
    from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address, IPv4Network, IPv6Network
except ImportError:
    from ansible_collections.community.general.plugins.module_utils.compat.ipaddress import (
        ip_address, IPv4Address, IPv6Address,
        ip_network, IPv4Network, IPv6Network
    )
import json
import shutil
import os
import pwd
import random
import re
import socket
import time
import xml.etree.ElementTree as ET
from tempfile import mkstemp


# Return an element in node, but return an empty element instead of None if not found
def xml_find(node, elt):
    res = node.find(elt)
    if res is None:
        res = ET.Element('')
        res.text = ''
    return res


class PFSenseModule(object):
    """ class managing pfsense base configuration """

    def __init__(self, module, config='/cf/conf/config.xml'):
        self.module = module
        self.config = config
        self.tree = ET.parse(config)
        self.root = self.tree.getroot()
        self.config_version = float(self.get_element('version').text)
        self.aliases = self.get_element('aliases', create_node=True)
        self.interfaces = self.get_element('interfaces')
        self.ifgroups = self.get_element('ifgroups')
        self.rules = self.get_element('filter')
        self.shapers = self.get_element('shaper')
        self.dnshapers = self.get_element('dnshaper')
        self.vlans = self.get_element('vlans')
        self.gateways = self.get_element('gateways')
        self.ipsec = self.get_element('ipsec')
        self.openvpn = self.get_element('openvpn')
        self.virtualip = self.get_element('virtualip')
        self.debug = open('/tmp/pfsense.debug', 'w')
        if sys.version_info >= (3, 4):
            self._scrub()

        self.pfsense_version = None

    # Work around pfSense CDATA xml formatting issue
    # https://github.com/opoplawski/ansible-pfsense/issues/61
    def _scrub(self):
        for elt in self.root.iter():
            if elt.text is not None:
                elt.text = html.unescape(elt.text)

    def get_interface_by_display_name(self, name):
        """ return interface_id by name """
        for interface in self.interfaces:
            descr_elt = interface.find('descr')
            if descr_elt is not None and descr_elt.text.strip().lower() == name.lower():
                return interface.tag
        return None

    def get_interface_by_port(self, name):
        """ return interface_id by port (os name) """
        for interface in self.interfaces:
            if interface.find('if').text.strip() == name:
                return interface.tag
        return None

    def get_interface_display_name(self, interface_id, return_none=False):
        """ return interface display name if found, otherwhise return the interface_id """
        if interface_id == 'enc0':
            return 'IPsec'
        if interface_id == 'openvpn':
            if return_none and not self.is_openvpn_enabled():
                return None
            return 'OpenVPN'

        for interface in self.interfaces:
            if interface.tag == interface_id:
                descr_elt = interface.find('descr')
                if descr_elt is not None:
                    return descr_elt.text.strip()
                break

        if return_none:
            return None
        return interface_id

    def get_interface_elt(self, interface_id):
        """ return interface """
        for interface in self.interfaces:
            if interface.tag == interface_id:
                return interface
        return None

    def get_interface_port(self, interface_id):
        """ return interface port """
        for interface in self.interfaces:
            if interface.tag == interface_id:
                return interface.find('if').text.strip()
        return None

    def get_interface_port_by_display_name(self, name):
        """ return interface port """
        for interface in self.interfaces:
            descr_elt = interface.find('descr')
            if descr_elt is not None and descr_elt.text.strip().lower() == name.lower():
                return interface.find('if').text.strip()
        return None

    def get_interfaces_networks(self):
        """ return interface local networks """
        ret = []
        for interface in self.interfaces:
            if interface.find('enable') is None:
                continue

            ipaddr_elt = interface.find('ipaddr')
            subnet_elt = interface.find('subnet')
            if ipaddr_elt is not None and subnet_elt is not None and ipaddr_elt.text is not None and subnet_elt.text is not None:
                ret.append('{0}/{1}'.format(ipaddr_elt.text, subnet_elt.text))

            ipaddr_elt = interface.find('ipaddrv6')
            subnet_elt = interface.find('subnetv6')
            if ipaddr_elt is not None and subnet_elt is not None and ipaddr_elt.text is not None and subnet_elt.text is not None:
                ret.append('{0}/{1}'.format(ipaddr_elt.text, subnet_elt.text))

            # TODO: add vip networks
        return ret

    def is_interface_port(self, interface_port):
        """ determines if arg is a pfsense interface port or not """
        for interface in self.interfaces:
            interface_elt = interface.tag.strip()
            if interface_elt == interface_port:
                return True
        return False

    def is_interface_display_name(self, name):
        """ determines if arg is an interface name or not """
        for interface in self.interfaces:
            descr_elt = interface.find('descr')
            if descr_elt is not None:
                if descr_elt.text.strip().lower() == name.lower():
                    return True
        return False

    def is_interface_group(self, name):
        """ determines if arg is an interface group name or not """
        if self.ifgroups is not None:
            for interface in self.ifgroups:
                ifname_elt = interface.find('ifname')
                if ifname_elt is not None:
                    # ifgroup names appear to be case sensitive
                    if ifname_elt.text.strip() == name:
                        return True
        return False

    def parse_interface(self, interface, fail=True, with_virtual=True, with_gwgroup=False):
        """ validate param interface field """
        if with_virtual and (interface == 'enc0' or interface.lower() == 'ipsec') and self.is_ipsec_enabled():
            return 'enc0'
        if with_virtual and (interface == 'openvpn' or interface.lower() == 'openvpn') and self.is_openvpn_enabled():
            return 'openvpn'
        if with_gwgroup and self.is_gateway_group(interface):
            return interface

        if self.is_interface_display_name(interface):
            return self.get_interface_by_display_name(interface)
        elif self.is_interface_port(interface):
            return interface
        elif self.is_interface_group(interface):
            return interface

        if fail:
            self.module.fail_json(msg='%s is not a valid interface' % (interface))
        return None

    @staticmethod
    def is_ipv4_address(address):
        """ test if address is a valid ipv4 address """
        try:
            addr = ip_address(u'{0}'.format(address))
            return isinstance(addr, IPv4Address)
        except ValueError:
            pass
        return False

    @staticmethod
    def is_ipv6_address(address):
        """ test if address is a valid ipv6 address """
        try:
            addr = ip_address(u'{0}'.format(address))
            return isinstance(addr, IPv6Address)
        except ValueError:
            pass
        return False

    @staticmethod
    def is_ipv4_network(address, strict=True):
        """ test if address is a valid ipv4 network """
        try:
            addr = ip_network(u'{0}'.format(address), strict=strict)
            return isinstance(addr, IPv4Network)
        except ValueError:
            pass
        return False

    @staticmethod
    def is_ipv6_network(address, strict=True):
        """ test if address is a valid ipv6 network """
        try:
            addr = ip_network(u'{0}'.format(address), strict=strict)
            return isinstance(addr, IPv6Network)
        except ValueError:
            pass
        return False

    def is_ip_network(self, address, strict=True):
        """ test if address is a valid ip network """
        return self.is_ipv4_network(address, strict) or self.is_ipv6_network(address, strict)

    def is_within_local_networks(self, address):
        """ test if address is contained in our local networks """
        networks = self.get_interfaces_networks()
        try:
            addr = ip_address(u'{0}'.format(address))
        except ValueError:
            return False

        for network in networks:
            try:
                net = ip_network(u'{0}'.format(network), strict=False)
                if addr in net:
                    return True
            except ValueError:
                # ignore invalid networks, keep trying
                pass
        return False

    @staticmethod
    def parse_ip_network(address, strict=True, returns_ip=True):
        """ return cidr parts of address """
        try:
            addr = ip_network(u'{0}'.format(address), strict=strict)
            if strict or not returns_ip:
                return (str(addr.network_address), addr.prefixlen)
            else:
                # we parse the address with ipaddr just for type checking
                # but we use a regex to return the result as it dont kept the address bits
                group = re.match(r'(.*)/(.*)', address)
                if group:
                    return (group.group(1), group.group(2))
        except ValueError:
            return None
        return None

    def parse_address(self, param, allow_self=True):
        """ validate param address field and returns it as a dict """
        if self.is_ipv6_address(param) or self.is_ipv6_network(param):
            addr = [param]
        else:
            addr = param.split(':', maxsplit=3)
            if len(addr) > 3:
                self.module.fail_json(msg='Cannot parse address %s' % (param))

        address = addr[0]

        ret = dict()
        # Check if the first character is "!"
        if address[0] == '!':
            # Invert the rule
            ret['not'] = None
            address = address[1:]

        if address == 'NET' or address == 'IP':
            interface = addr[1] if len(addr) > 1 else None
            ports = addr[2] if len(addr) > 2 else None
            if interface is None or interface == '':
                self.module.fail_json(msg='Cannot parse address %s' % (param))

            ret['network'] = self.parse_interface(interface)
            if address == 'IP':
                ret['network'] += 'ip'
        else:
            ports = addr[1] if len(addr) > 1 else None
            if address == 'any':
                ret['any'] = None
            # rule with this firewall
            elif allow_self and address == '(self)':
                ret['network'] = '(self)'
            # rule with interface name (LAN, WAN...)
            elif self.is_interface_display_name(address):
                ret['network'] = self.get_interface_by_display_name(address)
            else:
                if not self.is_ip_or_alias(address):
                    self.module.fail_json(msg='Cannot parse address %s, not IP or alias' % (address))
                ret['address'] = address

        if ports is not None:
            self.parse_port(ports, ret)
            msg = "the :ports syntax at end of addresses is deprecated and support will be removed soon. Please use source_port and destination_port options."
            self.module.warn(msg)

        return ret

    def parse_port(self, src_ports, ret):
        """ validate and parse port address field and set it in ret """
        ports = src_ports.split('-')
        if len(ports) > 2 or ports[0] is None or ports[0] == '' or len(ports) == 2 and (ports[1] is None or ports[1] == ''):
            self.module.fail_json(msg='Cannot parse port %s' % (src_ports))

        if not self.is_port_or_alias(ports[0]):
            self.module.fail_json(msg='Cannot parse port %s, not port number or alias' % (ports[0]))
        ret['port'] = ports[0]

        if len(ports) > 1:
            if not self.is_port_or_alias(ports[1]):
                self.module.fail_json(msg='Cannot parse port %s, not port number or alias' % (ports[1]))
            ret['port'] += '-' + ports[1]

    def check_name(self, name, objtype):
        """ check name validity """

        msg = None
        if len(name) >= 32 or len(re.findall(r'(^_*$|^\d*$|[^a-zA-Z0-9_])', name)) > 0:
            msg = f"The {objtype} name '{name}' must be less than 32 characters long, may not consist of only numbers, may not consist of only underscores, "
            msg += "and may only contain the following characters: a-z, A-Z, 0-9, _"
        elif name in ["port", "pass"]:
            msg = f"The {objtype} name must not be either of the reserved words 'port' or 'pass'"
        else:
            try:
                socket.getprotobyname(name)
                msg = f"The {objtype} name must not be an IP protocol name such as TCP, UDP, ICMP etc."
            except socket.error:
                # If the protocol name lookup fails, the name is not a reserved protocol and is therefore allowed.
                pass

            try:
                socket.getservbyname(name)
                msg = f"The {objtype} name must not be a well-known or registered TCP or UDP port name such as ssh, smtp, pop3, tftp, http, openvpn etc."
            except socket.error:
                # If the service name lookup fails, the name is not a reserved TCP/UDP service and is therefore allowed.
                pass

        if msg is not None:
            self.module.fail_json(msg=msg)

    def check_ip_address(self, address, ipprotocol, objtype, allow_networks=False, fail_ifnotip=False):
        """ check address according to ipprotocol """
        if address is None:
            return
        if allow_networks:
            ipv4 = self.is_ipv4_network(address, False)
            ipv6 = self.is_ipv6_network(address, False)
        else:
            ipv4 = self.is_ipv4_address(address)
            ipv6 = self.is_ipv6_address(address)

        if ipprotocol == 'inet':
            if ipv6 or not ipv4 and fail_ifnotip:
                self.module.fail_json(msg='{0} must use an IPv4 address'.format(objtype))
        elif ipprotocol == 'inet6':
            if ipv4 or not ipv6 and fail_ifnotip:
                self.module.fail_json(msg='{0} must use an IPv6 address'.format(objtype))
        elif ipprotocol == 'inet46':
            if ipv4 or ipv6:
                self.module.fail_json(msg='IPv4 and IPv6 addresses can not be used in objects that apply to both IPv4 and IPv6 (except within an alias).')

    def validate_openvpn_tunnel_network(self, network, ipproto):
        """ check openvpn tunnel network validity - based on pfSense's openvpn_validate_tunnel_network() """
        if network is not None and network != '':
            alias_elt = self.find_alias(network, aliastype='network')
            if alias_elt is not None:
                networks = alias_elt.find('address').text.split()
                if len(networks) > 1:
                    self.module.fail_json("The alias {0} contains more than one network".format(network))
                network = networks[0]

            if not self.is_ipv4_network(network, strict=False) and ipproto == 'ipv4':
                self.module.fail_json("{0} is not a valid IPv4 network".format(network))
            if not self.is_ipv6_network(network, strict=False) and ipproto == 'ipv6':
                self.module.fail_json("{0} is not a valid IPv6 network".format(network))
            return True

        return True

    def validate_string(self, name, objtype):
        """ check string validity - similar to pfSense's do_input_validate() """

        if len(re.findall(r'[\000-\010\013\014\016-\037]', name)) > 0:
            self.module.fail_json("The {0} name contains invalid characters.".format(objtype))

    @staticmethod
    def addr_normalize(addr):
        """ return address element formatted like module argument """
        address = ''
        ports = ''
        if 'address' in addr:
            address = addr['address']
        if 'any' in addr:
            address = 'any'
        if 'network' in addr:
            address = 'NET:%s' % addr['network']
        if address == '':
            raise ValueError('UNKNOWN addr %s' % addr)
        if 'port' in addr:
            ports = addr['port']
        if 'not' in addr:
            address = '!' + address
        return address, ports

    @staticmethod
    def new_element(tag, text='\n\t\t\t'):
        """ Create and return new XML configuration element  """
        elt = ET.Element(tag)
        # Attempt to preserve some of the formatting of pfSense's config.xml
        elt.text = text
        elt.tail = '\n\t\t'
        return elt

    def get_element(self, node, root_elt=None, create_node=False):
        """ return <node> configuration element """
        if root_elt is None:
            root_elt = self.root
        top_elt = root_elt
        for item in node.split('/'):
            elt = top_elt.find(item)
            if elt is None and create_node:
                elt = self.new_element(item)
                top_elt.append(elt)
            top_elt = elt
        return elt

    def get_elements(self, node, root_elt=None):
        """ return all <node> configuration elements  """
        if root_elt is None:
            root_elt = self.root
        return root_elt.findall(node)

    def get_index(self, elt, root_elt=None):
        """ Get elt index  """
        if root_elt is None:
            root_elt = self.root
        return list(root_elt).index(elt)

    def find_elt(self, node, search_text, search_field='descr', root_elt=None, multiple_ok=False):
        """ return object elt if found """
        search_xpath = "{0}[{1}='{2}']".format(node, search_field, search_text)
        return self.find_elt_xpath(search_xpath, root_elt, multiple_ok)

    def find_elt_xpath(self, search_xpath, root_elt=None, multiple_ok=False):
        """ return object elt if found """
        if root_elt is None:
            root_elt = self.root
        result = root_elt.findall(search_xpath)
        # Always return an iterable if multiple_ok
        if multiple_ok:
            return result
        else:
            if len(result) == 1:
                return result[0]
            elif len(result) > 1:
                self.module.fail_json(msg='Found multiple elements for name {0}.'.format(self.obj['name']))
        return None

    @staticmethod
    def remove_deleted_param_from_elt(elt, param, params):
        """ Remove from a deleted param from an xml elt """
        changed = False
        if param not in params:
            param_elt = elt.find(param)
            if param_elt is not None:
                changed = True
                elt.remove(param_elt)
        return changed

    def is_ipsec_enabled(self):
        """ return True if ipsec is enabled """
        if self.ipsec is None:
            return False

        for elt in self.ipsec:
            if elt.tag == 'phase1' and elt.find('disabled') is None:
                return True
        return False

    def is_openvpn_enabled(self):
        """ return True if openvpn is enabled """
        if self.openvpn is None:
            return False

        for elt in self.openvpn:
            if elt.tag == 'openvpn-server' or elt.tag == 'openvpn-client':
                return True
        return False

    def find_ipsec_phase1(self, field_value, field='descr'):
        """ return ipsec phase1 elt if found """
        for ipsec_elt in self.ipsec:
            if ipsec_elt.tag != 'phase1':
                continue

            field_elt = ipsec_elt.find(field)
            if field_elt is not None and field_elt.text == field_value:
                return ipsec_elt

        return None

    @staticmethod
    def rule_match_interface(rule_elt, interface, floating):
        """ check if a rule elt match the targeted interface
            floating rules must match the floating mode instead of the interface name
        """
        interface_elt = rule_elt.find('interface')
        floating_elt = rule_elt.find('floating')
        if floating_elt is not None:
            return floating
        elif floating:
            return False
        return interface_elt is not None and interface_elt.text.lower() == interface.lower()

    def get_interface_rules_count(self, interface, floating):
        """ get rules count in interface/floating """
        count = 0
        for rule_elt in self.rules:
            if not self.rule_match_interface(rule_elt, interface, floating):
                continue
            count += 1

        return count

    def get_rule_position(self, descr, interface, floating, first=True):
        """ get rule position in interface/floating """
        i = 0
        found = None
        for rule_elt in self.rules:
            if not self.rule_match_interface(rule_elt, interface, floating):
                continue
            descr_elt = rule_elt.find('descr')
            if descr_elt is not None and descr_elt.text == descr:
                if first:
                    return i
                else:
                    found = i
            i += 1

        return found

    def copy_dict_to_element(self, src, top_elt, sub=0, prev_elt=None):
        """ Copy/update top_elt from src """
        changed = False
        for (key, value) in src.items():
            this_elt = top_elt.find(key)
            self.debug.write('changed=%s key=%s value=%s this_elt=%s, sub=%d\n' % (changed, key, value, this_elt, sub))
            if this_elt is None:
                if isinstance(value, dict):
                    changed = True
                    self.debug.write('calling copy_dict_to_element()\n')
                    # Create a new element
                    new_elt = ET.Element(key)
                    new_elt.text = '\n%s' % ('\t' * (sub + 4))
                    new_elt.tail = '\n%s' % ('\t' * (sub + 2))
                    if prev_elt is not None:
                        prev_elt.tail = '\n%s' % ('\t' * (sub + 2))
                    prev_elt = new_elt
                    self.copy_dict_to_element(value, new_elt, sub=sub + 1, prev_elt=prev_elt)
                    top_elt.append(new_elt)
                elif isinstance(value, list):
                    if value:
                        changed = True
                        if prev_elt is not None:
                            prev_elt.tail = '\n%s' % ('\t' * (sub + 2))
                        for item in value:
                            new_elt = self.new_element(key)
                            prev_elt = new_elt
                            if isinstance(item, dict):
                                self.copy_dict_to_element(item, new_elt, sub=sub + 1, prev_elt=prev_elt)
                            else:
                                new_elt.text = item
                            top_elt.append(new_elt)
                else:
                    changed = True
                    # Create a new element
                    new_elt = ET.Element(key)
                    new_elt.text = value
                    new_elt.tail = '\n%s' % ('\t' * (sub + 2))
                    if prev_elt is not None:
                        prev_elt.tail = '\n%s' % ('\t' * (sub + 2))
                    prev_elt = new_elt
                    top_elt.append(new_elt)
                self.debug.write('changed=%s added key=%s value=%s tag=%s\n' % (changed, key, value, top_elt.tag))
            else:
                if isinstance(value, dict):
                    self.debug.write('calling copy_dict_to_element()\n')
                    if self.copy_dict_to_element(value, this_elt, sub=sub + 1, prev_elt=this_elt):
                        changed = True
                elif isinstance(value, list):
                    all_sub_elts = top_elt.findall(key)

                    # remove extra elts
                    while len(all_sub_elts) > len(value):
                        top_elt.remove(all_sub_elts.pop())
                        changed = True

                    # add new elts
                    while len(all_sub_elts) < len(value):
                        new_elt = self.new_element(key)
                        top_elt.append(new_elt)
                        all_sub_elts.append(new_elt)
                        changed = True
                        prev_elt = new_elt

                    # set all elts
                    for idx, item in enumerate(value):
                        if isinstance(item, str):
                            if all_sub_elts[idx].text is None and item == '':
                                pass
                            elif all_sub_elts[idx].text != item:
                                all_sub_elts[idx].text = item
                                changed = True
                        elif self.copy_dict_to_element(item, all_sub_elts[idx], sub=sub + 1, prev_elt=prev_elt):
                            changed = True
                elif this_elt.text is None and value == '':
                    pass
                elif this_elt.text != value:
                    this_elt.text = value
                    changed = True
                    self.debug.write('changed=%s this_elt.text=%s != value=%s\n' % (changed, repr(this_elt.text), repr(value)))
                prev_elt = this_elt

        # Sub-elements must be completely described, so remove any missing elements
        if sub:
            for child_elt in list(top_elt):
                if child_elt.tag not in src:
                    changed = True
                    self.debug.write('changed=%s removed tag=%s\n' % (changed, child_elt.tag))
                    top_elt.remove(child_elt)

        if prev_elt is not None:
            prev_elt.tail = '\n%s' % ('\t' * (sub + 1))

        self.debug.flush()
        return changed

    @staticmethod
    def array_to_php(src, php_name):
        """ Generate PHP commands to initialiaze a variable with contents of an array """
        array_values = "'" + "','".join(src) + "'"
        cmd = f"${php_name} = array({array_values});\n"
        return cmd

    @staticmethod
    def dict_to_php(src, php_name):
        """ Generate PHP commands to initialiaze a variable with contents of a dict """
        cmd = "${0} = array();\n".format(php_name)
        for key, value in src.items():
            if value is not None:
                cmd += "${0}['{1}'] = '{2}';\n".format(php_name, key, value)
            else:
                cmd += "${0}['{1}'] = '';\n".format(php_name, key)
        return cmd

    @staticmethod
    def element_to_dict(src_elt):
        """ Create dict from XML src_elt """
        res = {}
        for elt in src_elt:
            if len(elt) > 0:
                value = PFSenseModule.element_to_dict(elt)
            else:
                value = elt.text if elt.text is not None else ''

            if elt.tag in res:
                if not isinstance(res[elt.tag], list):
                    res[elt.tag] = [res[elt.tag]]
                res[elt.tag].append(value)
            else:
                res[elt.tag] = value
        return res

    def config_get_path(self, name, default=None):
        """ get value of a specific configuration path """
        elt = self.find_elt_xpath(name)
        if elt is not None:
            return elt.text
        else:
            return default

    def get_refid(self, node, name):
        """ get refid of name in specific nodes """
        elt = self.find_elt(node, name)
        if elt is not None:
            return xml_find(elt, 'refid').text
        else:
            return None

    def get_caref(self, name):
        """ get CA refid for name """
        # global is a special case
        if name == 'global':
            return 'global'
        # Otherwise search the ca elements
        return self.get_refid('ca', name)

    def get_certref(self, name):
        """ get Cert refid for name """
        return self.get_refid('cert', name)

    def get_crlref(self, name):
        """ get CRL refid for name """
        return self.get_refid('crl', name)

    @staticmethod
    def get_username():
        """ get username logged """
        username = pwd.getpwuid(os.getuid()).pw_name
        if os.environ.get('SUDO_USER'):
            username = os.environ.get('SUDO_USER')
        # sudo masks this
        sshclient = os.environ.get('SSH_CLIENT')
        if sshclient:
            username = username + '@' + sshclient
        return username

    def find_alias(self, name, aliastype=None):
        """ return alias named name, having type aliastype if specified """
        for alias in self.aliases:
            if xml_find(alias, 'name').text == name and (aliastype is None or xml_find(alias, 'type').text == aliastype):
                return alias
        return None

    def is_ip_or_alias(self, address):
        """ return True if address is an ip or an alias """
        # Is it an alias?
        if (self.find_alias(address, 'host') is not None
                or self.find_alias(address, 'network') is not None
                or self.find_alias(address, 'urltable') is not None):
            return True

        # Is it an IP address or network?
        if self.is_ipv4_address(address) or self.is_ipv4_network(address) or self.is_ipv6_address(address) or self.is_ipv6_network(address):
            return True

        # None of the above
        return False

    def is_gateway_group(self, gwgroup):
        """ return True if gwgroup is a gateway group """
        return self.find_elt_xpath(f"./gateways/gateway_group[name='{gwgroup}']") is not None

    def is_port_or_alias(self, port):
        """ return True if port is a valid port number or an alias """
        if (self.find_alias(port, 'port') is not None
                or self.find_alias(port, 'urltable_ports') is not None):
            return True
        try:
            if int(port) > 0 and int(port) < 65536:
                return True
        except ValueError:
            pass
        return False

    def is_virtual_ip(self, addr):
        """ return True if addr is a virtual ip """
        if self.virtualip is None:
            return False

        if self.find_elt('vip', addr, 'subnet', root_elt=self.virtualip) is None:
            return False

        return True

    def get_virtual_ip_interface(self, vip):
        """ return interface name for virtual IP name or network """
        if self.virtualip is None:
            return None

        vip_elt = self.find_elt('vip', vip, 'descr', root_elt=self.virtualip)
        if vip_elt is None:
            vip_elt = self.find_elt('vip', vip, 'subnet', root_elt=self.virtualip)

        if vip_elt is None:
            return None

        uniqid_elt = vip_elt.find('uniqid')
        if uniqid_elt is None:
            return None

        return "_vip" + xml_find(vip_elt, 'uniqid').text

    def find_queue(self, name, interface=None, enabled=False):
        """ return QOS queue if found """

        # iterate each interface
        for shaper_elt in self.shapers:
            if interface is not None:
                interface_elt = shaper_elt.find('interface')
                if interface_elt is None or interface_elt.text != interface:
                    continue

            if enabled:
                enabled_elt = shaper_elt.find('enabled')
                if enabled_elt is None or enabled_elt.text != 'on':
                    continue

            # iterate each queue
            for queue_elt in shaper_elt.findall('.//queue'):
                name_elt = queue_elt.find('name')
                if name_elt is None or name_elt.text != name:
                    continue

                if enabled:
                    enabled_elt = queue_elt.find('enabled')
                    if enabled_elt is None or enabled_elt.text != 'on':
                        continue

                # found it
                return queue_elt

        return None

    def find_limiter(self, name, enabled=False):
        """ return QOS limiter if found """

        # iterate each queue
        for queue_elt in self.dnshapers:
            if enabled:
                enabled_elt = queue_elt.find('enabled')
                if enabled_elt is None or enabled_elt.text != 'on':
                    continue

            name_elt = queue_elt.find('name')
            if name_elt is None or name_elt.text != name:
                continue

            return queue_elt

        return None

    def find_vlan(self, interface, tag):
        """ return vlan elt if found """
        if self.vlans is None:
            self.vlans = self.get_element('vlans')

        if self.vlans is not None:
            for vlan in self.vlans:
                if xml_find(vlan, 'if').text == interface and xml_find(vlan, 'tag').text == tag:
                    return vlan

        return None

    def _create_gw_elt(self, name, interface_id, protocol):
        gw_elt = ET.Element('gateway_item')
        gw_elt.append(self.new_element('interface', interface_id))
        gw_elt.append(self.new_element('gateway', 'dynamic'))
        gw_elt.append(self.new_element('name', name))
        gw_elt.append(self.new_element('weight', '1'))
        gw_elt.append(self.new_element('ipprotocol', protocol))
        gw_elt.append(self.new_element('descr', 'Interface ' + name + ' Gateway'))
        return gw_elt

    def find_gateway_elt(self, name, interface=None, protocol=None, dhcp=False, vti=False):
        """ return gateway elt if found """
        for gw_elt in self.gateways:
            if gw_elt.tag != 'gateway_item':
                continue

            if protocol is not None and xml_find(gw_elt, 'ipprotocol').text != protocol:
                continue

            if interface is not None and xml_find(gw_elt, 'interface').text != interface:
                continue

            if xml_find(gw_elt, 'name').text == name:
                return gw_elt

        for interface_elt in self.interfaces:
            descr_elt = interface_elt.find('descr')
            if descr_elt is None or descr_elt.text is None:
                continue

            if_elt = interface_elt.find('if')
            if if_elt is None or if_elt.text is None:
                continue

            descr_text = descr_elt.text.strip().upper()

            # todo: implement interface match with ipsec tunnels threw vtimaps
            if vti and (protocol is None or protocol == 'inet') and if_elt.text.startswith('ipsec') and descr_text + '_VTIV4' == name:
                return self._create_gw_elt(name, interface_elt.tag, 'inet')

            if vti and (protocol is None or protocol == 'inet6') and if_elt.text.startswith('ipsec') and descr_text + '_VTIV6' == name:
                return self._create_gw_elt(name, interface_elt.tag, 'inet6')

            if dhcp:
                ipaddr_elt = interface_elt.find('ipaddr')
                if (protocol is None or protocol == 'inet') and ipaddr_elt is not None and ipaddr_elt.text == 'dhcp' and descr_text + "_DHCP" == name:
                    return self._create_gw_elt(name, interface_elt.tag, 'inet')

                ipaddr_elt = interface_elt.find('ipaddrv6')
                if (protocol is None or protocol == 'inet6') and ipaddr_elt is not None and ipaddr_elt.text == 'dhcp6' and descr_text + "_DHCP6" == name:
                    return self._create_gw_elt(name, interface_elt.tag, 'inet6')

        return None

    def find_gateway_group_elt(self, name, protocol='inet'):
        """ return gateway_group elt if found """
        for gw_grp_elt in self.gateways:
            if gw_grp_elt.tag != 'gateway_group':
                continue
            if xml_find(gw_grp_elt, 'name').text != name:
                continue

            # check if protocol match
            match_protocol = True
            for gw_elt in gw_grp_elt:
                if gw_elt.tag != 'item' or gw_elt.text is None:
                    continue

                items = gw_elt.text.split('|')
                if not items or self.find_gateway_elt(items[0], None, protocol) is None:
                    match_protocol = False
                    break

            if not match_protocol:
                continue

            return gw_grp_elt

        return None

    def find_active_gateways(self):
        """ returns list of active gateways """
        (retcode, raw_output, error) = self.phpshell("playback gatewaystatus")

        write = False
        output = []
        lines = raw_output.split("\n")
        for line in lines:
            if write and line != "" and "shell:" not in line:
                output.append(line)
            if "started" in line:
                write = True

        head = output[0].split()
        data = []

        for line in output[1:]:
            c = 0
            dline = {}
            for item in line.split():
                dline[head[c]] = item
                c += 1
            if dline is not {}:
                data.append(dline)
        return data

    def find_ca_elt(self, ca, search_field='descr'):
        """ return certificate authority elt if found """
        return self.find_elt('ca', ca, search_field)

    def find_cert_elt(self, cert, search_field='descr'):
        """ return certificate elt if found """
        return self.find_elt('cert', cert, search_field)

    def find_crl_elt(self, crl, search_field='descr'):
        """ return certificate revocation list elt if found """
        return self.find_elt('crl', crl, search_field)

    def find_schedule_elt(self, name):
        """ return schedule elt if found """
        return self.find_elt_xpath("./schedules/schedule[name='{0}']".format(name))

    @staticmethod
    def uniqid(prefix='', more_entropy=False):
        """ return an identifier based on time """
        if more_entropy:
            return prefix + '{0:x}{1:05x}{2:.8F}'.format(int(time.time()), int(time.time() * 1000000) % 0x100000, random.random() * 10)

        return prefix + '{0:x}{1:05x}'.format(int(time.time()), int(time.time() * 1000000) % 0x100000)

    def phpshell(self, command, debug=True):
        """ Run a command in the php developer shell """
        phpshell = "global $config;\n"
        if debug:
            phpshell = "global $debug;\n$debug = 1;\n"
        phpshell += command + "\nexec\nexit"
        # Dummy argument suppresses displaying help message
        return self.module.run_command('/usr/local/sbin/pfSsh.php dummy', data=phpshell)

    def php(self, command):
        """ Run a command in php and return the output """
        cmd = '<?php\n'
        cmd += command
        cmd += '\n?>\n'
        (dummy, stdout, stderr) = self.module.run_command('/usr/local/bin/php', data=cmd)
        # If /var/run/booting is in place, various requires will emit a "."
        (stdout, nsubs) = re.subn(r'^\.+', '', stdout)
        if nsubs > 0:
            self.module.warn('/var/run/booting appears to be present, confirm successful boot and remove if appropriate.')
        # TODO: check stderr for errors
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as e:
            self.module.fail_json(msg=f"{e}", cmd=cmd, stdout=stdout, stderr=stderr)
        return result

    def write_config(self, descr='Updated by ansible pfsense module'):
        """ Generate config file """
        revision = self.get_element('revision')
        xml_find(revision, 'time').text = '%d' % time.time()
        revdescr = revision.find('description')
        if revdescr is None:
            revdescr = ET.Element('description')
            revision.append(revdescr)
        revdescr.text = descr
        username = self.get_username()
        xml_find(revision, 'username').text = username
        (tmp_handle, tmp_name) = mkstemp()
        os.close(tmp_handle)
        if sys.version_info >= (3, 4):
            self.tree.write(tmp_name, xml_declaration=True, method='xml', short_empty_elements=False)
        else:
            self.tree.write(tmp_name, xml_declaration=True, method='xml')
        shutil.move(tmp_name, self.config)
        os.chmod(self.config, 0o644)
        try:
            os.remove('/tmp/config.cache')
        except OSError as exception:
            if exception.errno == 2:
                # suppress "No such file or directory error
                pass
            else:
                raise

    @staticmethod
    def get_version():
        """ get pfSense version """
        # TODO: use subprocess when we'll drop support for python 2.7
        os.system("pkg-static info | grep pfSense-base > /tmp/pfVersion")
        vfile = open("/tmp/pfVersion", "r")
        version = vfile.read().replace("pfSense-base-", "").split()[0]
        vfile.close()
        return version

    @staticmethod
    def is_ce_version(version=None):
        """ return True if version is a CE version (for now, we only have 2.x patterns) """
        if isinstance(version, list):
            return version[0] == 2
        if version is None:
            version = PFSenseModule.get_version()
        return len(version.split('.')[0]) == 1

    def is_version(self, version, or_more=True):
        """ check target pfSense version """
        if self.pfsense_version is None:
            pfsense_version = self.get_version()
            self.pfsense_version = []
            match = re.match(r'(\d+)\.(\d+)\.?(\d+)?', pfsense_version)
            if match is None:
                self.module.fail_json(msg="Unable to get version from pfSense (got '{0}')".format(pfsense_version))
            for idx in range(0, match.lastindex):
                self.pfsense_version.append(int(match.group(idx + 1)))

        # we must compare a CE with a CE or pfSense+ with pfSense+
        is_ce_in = self.is_ce_version(version)
        is_ce = self.is_ce_version(self.pfsense_version)
        if is_ce != is_ce_in:
            return False

        for idx, ver in enumerate(version):
            if idx == len(self.pfsense_version):
                return True
            if self.pfsense_version[idx] > ver and or_more:
                return True

            if ver < self.pfsense_version[idx] and not or_more or ver > self.pfsense_version[idx]:
                return False

        return True

    def is_at_least_2_5_2(self):
        """ check target pfSense version """
        return self.is_version([2, 5, 2]) or self.is_version([21, 5])

    def is_at_least_2_5_0(self):
        """ check target pfSense version """
        return self.is_version([2, 5, 0]) or self.is_version([21, 2])

    def apply_ipsec_changes(self):
        """ execute pfSense code to appy ipsec changes """
        if self.is_at_least_2_5_0():
            return self.phpshell(
                "require_once('vpn.inc');"
                "$ipsec_dynamic_hosts = ipsec_configure();"
                "ipsec_reload_package_hook();"
                "$retval = 0;"
                "$retval |= filter_configure();"
                "if ($ipsec_dynamic_hosts >= 0 && is_subsystem_dirty('ipsec'))"
                "    clear_subsystem_dirty('ipsec');"
            )
        return self.phpshell(
            "require_once('vpn.inc');"
            "$ipsec_dynamic_hosts = vpn_ipsec_configure();"
            "$retval = 0;"
            "$retval |= filter_configure();"
            "if ($ipsec_dynamic_hosts >= 0 && is_subsystem_dirty('ipsec'))"
            "   clear_subsystem_dirty('ipsec');"
        )
