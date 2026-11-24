# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import sys
if sys.version_info >= (3, 4):
    import html
    from html.entities import name2codepoint
try:
    from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address, IPv4Network, IPv6Network
except ImportError:
    from ansible_collections.community.general.plugins.module_utils.compat.ipaddress import (
        ip_address, IPv4Address, IPv6Address,
        ip_network, IPv4Network, IPv6Network
    )
import json
import errno
import fcntl
import hashlib
import os
import pwd
import random
import re
import socket
import stat
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from tempfile import mkstemp
from xml.dom import minidom, Node
from xml.parsers.expat import ExpatError, ParserCreate

XML_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}
HTML4_ENTITIES = {name: chr(codepoint) for name, codepoint in name2codepoint.items()}


class PFSenseConfigError(Exception):
    """A configuration transaction cannot safely be committed."""

    def __init__(self, message, mismatch=None, native_validation=None):
        super(PFSenseConfigError, self).__init__(message)
        self.mismatch = mismatch
        self.native_validation = native_validation


# Return an element in node, but return an empty element instead of None if not found
def xml_find(node, elt):
    res = node.find(elt)
    if res is None:
        res = ET.Element("")
        res.text = ""
    return res


class PFSenseModule(object):
    """ class managing pfsense base configuration """

    def __init__(self, module, config="/cf/conf/config.xml",
                 config_lock="/tmp/config.lock", config_cache="/tmp/config.cache"):
        self.module = module
        self.config = config
        self.config_lock = config_lock
        self.config_cache = config_cache
        try:
            self._legacy_html_entities = self._uses_legacy_html_entities()
            # Read bytes once, so the tree and conflict-detection hash describe
            # exactly the same snapshot. Never hold this lock across PHP hooks.
            with self._locked_config():
                with open(config, "rb") as source:
                    original = source.read()
            self.tree = self._parse_config(original, self._legacy_html_entities)
            self._validate_config(self.tree)
            self._config_digest = hashlib.sha256(original).digest()
            self._required_sections = {
                tag: len(self.tree.getroot().find(tag)) > 0
                for tag in ("system", "interfaces")
                if self.tree.getroot().find(tag) is not None
            }
        except (OSError, ValueError, ET.ParseError, ExpatError, PFSenseConfigError) as error:
            self.module.fail_json(msg="Unable to read pfSense configuration safely: {0}".format(error))
        self.root = self.tree.getroot()
        self.config_version = float(self.get_element("version").text)
        self.aliases = self.get_element("aliases", create_node=True)
        self.interfaces = self.get_element("interfaces")
        self.ifgroups = self.get_element("ifgroups")
        self.rules = self.get_element("filter")
        self.shapers = self.get_element("shaper")
        self.dnshapers = self.get_element("dnshaper")
        self.vlans = self.get_element("vlans")
        self.gateways = self.get_element("gateways")
        self.ipsec = self.get_element("ipsec")
        self.openvpn = self.get_element("openvpn")
        self.virtualip = self.get_element("virtualip")
        self.debug = open("/tmp/pfsense.debug", "w")
        self.pfsense_version = None

    @staticmethod
    def _uses_legacy_html_entities():
        # Inspect the installed parser rather than invoking PHP on every
        # read-only rule check or relying on product/config version numbers.
        try:
            with open("/etc/inc/xmlparse.inc", "rb") as source:
                return re.search(rb"html_entity_decode\s*\(\s*\$data\s*\)", source.read()) is not None
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise
            return False

    @staticmethod
    def _decode_xml_entities(value, legacy_html_entities=False):
        """Decode one native entity layer, without HTML5 substitutions."""
        if "&" not in value:
            return value
        entities = HTML4_ENTITIES if legacy_html_entities else XML_ENTITIES

        def decode(match):
            entity = match.group(1)
            if not entity.startswith("#"):
                return entities.get(entity, match.group(0))
            codepoint = int(entity[2:], 16) if entity.startswith("#x") else int(entity[1:])
            if (codepoint in (9, 10, 13) or 0x20 <= codepoint <= 0xD7FF
                    or 0xE000 <= codepoint <= 0xFFFD or 0x10000 <= codepoint <= 0x10FFFF):
                return chr(codepoint)
            return match.group(0)

        return re.sub(r"&([A-Za-z][A-Za-z0-9]*|#[0-9]+|#x[0-9a-fA-F]+);", decode, value)

    @classmethod
    def _parse_config(cls, data, legacy_html_entities=False):
        # Ordinary XML text is already entity-decoded by the XML parser.
        # Only pfSense's escaped CDATA needs another XML-only decoding pass.
        # Decoding concatenated ordinary text again corrupts literal '&amp;'
        # read from '&amp;amp;'. Native PHP emits the '&' and 'amp;' separately.
        # Build the ElementTree directly. A DOM -> XML -> ElementTree round
        # trip is expensive on every rule invocation, including no-op runs.
        builder = ET.TreeBuilder()
        parser = ParserCreate(namespace_separator="}")
        cdata = None

        def qualified(name):
            return "{" + name if "}" in name else name

        def start(name, attributes):
            if attributes:
                attributes = {qualified(key): value for key, value in attributes.items()}
            builder.start(qualified(name), attributes)

        def text(value):
            if cdata is None:
                builder.data(value)
            else:
                cdata.append(value)

        def start_cdata():
            nonlocal cdata
            cdata = []

        def end_cdata():
            nonlocal cdata
            # Expat can split character data at newlines or other boundaries.
            # Decode a complete CDATA section once, preserving multiline text
            # and entity references split across callbacks.
            builder.data(cls._decode_xml_entities("".join(cdata), legacy_html_entities))
            cdata = None

        parser.StartElementHandler = start
        parser.EndElementHandler = lambda name: builder.end(qualified(name))
        parser.CharacterDataHandler = text
        parser.StartCdataSectionHandler = start_cdata
        parser.EndCdataSectionHandler = end_cdata
        parser.Parse(data, True)
        return ET.ElementTree(builder.close())

    @classmethod
    def _config_values(cls, element):
        """Match native named fields and ordered lists, ignoring formatting."""
        text = element.text or ""
        text = text.strip("\t\n\r") if text.strip() else ""
        groups = cls._group_config_children(element)
        # Native PHP stores named children in an associative array and repeated
        # tags in ordered lists. A newly appended server can follow a client in
        # Python XML, but PHP emits it beside the other servers. Preserve order
        # *within* each tag's list, particularly filter/rule and NAT rule lists.
        return (element.tag, element.attrib, text,
                tuple((tag, tuple(cls._config_values(child) for child in groups[tag]))
                      for tag in sorted(groups)))

    @staticmethod
    def _group_config_children(element):
        groups = {}
        for child in element:
            groups.setdefault(child.tag, []).append(child)
        return groups

    @classmethod
    def _config_difference(cls, expected, actual, path=None):
        """Return the first differing field path and reason, never its value."""
        path = path or "/{0}[1]".format(expected.tag)
        left, right = cls._config_values(expected), cls._config_values(actual)
        if left == right:
            return None
        for index, reason in ((0, "element name differs"), (1, "attributes differ"), (2, "text differs")):
            if left[index] != right[index]:
                return {"path": path, "reason": reason}
        expected_groups = cls._group_config_children(expected)
        actual_groups = cls._group_config_children(actual)
        for tag in sorted(set(expected_groups) | set(actual_groups)):
            expected_children = expected_groups.get(tag, [])
            actual_children = actual_groups.get(tag, [])
            if len(expected_children) != len(actual_children):
                return {"path": "{0}/{1}[{2}]".format(
                    path, tag, min(len(expected_children), len(actual_children)) + 1),
                    "reason": "element count differs"}
            for index, (expected_child, actual_child) in enumerate(zip(expected_children, actual_children), 1):
                difference = cls._config_difference(
                    expected_child, actual_child, "{0}/{1}[{2}]".format(path, tag, index))
                if difference is not None:
                    return difference
        return None

    def _serialize_config(self):
        # This is a private transport document, not the final on-disk format.
        # Encode values in escaped CDATA so the native parser receives their
        # literal contents. dump_xml_config() chooses the final CDATA fields,
        # XML entity spelling, indentation, declaration, and end tags.
        # ElementTree leaves carriage returns literal in text. Protect them
        # from XML newline normalization in this intermediate DOM parse.
        document = minidom.parseString(ET.tostring(self.root, encoding="utf-8").replace(b"\r", b"&#13;"))
        try:
            for element in document.getElementsByTagName("*"):
                # minidom otherwise collapses empty elements to <enable/>.
                # An empty text child preserves pfSense's explicit end tags.
                if not element.childNodes:
                    element.appendChild(document.createTextNode(""))
                for child in list(element.childNodes):
                    if child.nodeType == Node.TEXT_NODE:
                        # Quotes need no escaping inside CDATA. Legacy PHP
                        # html_entity_decode() defaults may leave apostrophe
                        # entities untouched, changing e.g. OpenVPN 'nopool'.
                        escaped = html.escape(child.data, quote=False).replace("\r", "&#13;")
                        if child.data:
                            element.replaceChild(document.createCDATASection(escaped), child)
            return document.toxml(encoding="utf-8")
        finally:
            document.unlink()

    def _validate_config(self, tree):
        root = tree.getroot()
        versions = root.findall("version")
        if root.tag != "pfsense" or len(versions) != 1:
            raise PFSenseConfigError("Expected a pfsense root and exactly one configuration version")
        if not re.match(r"^\d+(?:\.\d+)?$", versions[0].text or ""):
            raise PFSenseConfigError("Invalid configuration version")
        for tag, had_children in getattr(self, "_required_sections", {}).items():
            sections = root.findall(tag)
            if len(sections) != 1 or (had_children and len(sections[0]) == 0):
                raise PFSenseConfigError("Refusing to remove required configuration section: {0}".format(tag))

    @contextmanager
    def _locked_config(self):
        # Match lock('config', LOCK_EX) in pfSense's util.inc. The lock file
        # must remain in place: unlinking it would allow locks on two inodes.
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.config_lock, flags, 0o666)
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as error:
                    if error.errno not in (errno.EACCES, errno.EAGAIN):
                        raise
                    if time.monotonic() >= deadline:
                        raise PFSenseConfigError("Timed out waiting for the native config lock")
                    time.sleep(0.1)
            yield
        finally:
            os.close(descriptor)

    @staticmethod
    def _atomic_replace(path, data, metadata, mode, validate=None):
        descriptor, temporary = mkstemp(prefix="." + os.path.basename(path) + ".",
                                        dir=os.path.dirname(os.path.abspath(path)))
        try:
            with os.fdopen(descriptor, "wb") as output:
                current = os.fstat(output.fileno())
                if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
                    os.fchown(output.fileno(), metadata.st_uid, metadata.st_gid)
                os.fchmod(output.fileno(), mode)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            if validate is not None:
                validate(temporary)
                # The native formatter rewrites only this temporary file.
                # Sync and hash those final bytes, not the transport document.
                with open(temporary, "r+b") as candidate:
                    data = candidate.read()
                    os.fsync(candidate.fileno())
            # No cross-filesystem copy fallback: this must be an atomic rename.
            os.replace(temporary, path)
            return data
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _sync_config_directory(self):
        descriptor = os.open(os.path.dirname(os.path.abspath(self.config)), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _validate_native_config(self, path):
        # Only load the standalone XML parser, not config.inc or pfSsh.php:
        # those can read/recover the live config or run hooks while locked.
        # Use the deployed firewall's serializer as the formatting authority,
        # including packages. Never expose configuration values or PHP errors.
        command = r"""
ini_set('display_errors', '0');
$stage = 10;
try {
    require_once('/etc/inc/xmlparse.inc');
    $stage = 11;
    $parsed = parse_xml_config($argv[1], array('pfsense'));
    if (!is_array($parsed) || empty($parsed)) {
        exit($stage);
    }
    $stage = 12;
    $xml = dump_xml_config($parsed, 'pfsense');
    $stage = 13;
    if (file_put_contents($argv[1], $xml) !== strlen($xml)) {
        exit($stage);
    }
    // Reject a native formatting round trip that changes values or structure.
    $stage = 14;
    $roundtrip = parse_xml_config($argv[1], array('pfsense'));
    if (!is_array($roundtrip) || empty($roundtrip)) {
        exit($stage);
    }
    exit($parsed === $roundtrip ? 0 : 15);
} catch (\Throwable $error) {
    exit($stage);
}
"""
        result, unused_stdout, unused_stderr = self.module.run_command(
            ["/usr/local/bin/php", "-r", command, path])
        if result != 0:
            stage = {
                10: "load_parser", 11: "parse_candidate", 12: "serialize_candidate",
                13: "write_formatted_candidate", 14: "parse_formatted_candidate",
                15: "compare_native_roundtrip",
            }.get(result, "php_command")
            mismatch = None
            if result == 15:
                # The formatted candidate exists, so locate any changed field
                # without disclosing either its intended or formatted value.
                with open(path, "rb") as candidate:
                    formatted = self._parse_config(candidate.read(), self._legacy_html_entities)
                mismatch = self._config_difference(self.root, formatted.getroot())
            raise PFSenseConfigError(
                "Native pfSense XML validation/formatting failed at {0} (PHP exit {1}); "
                "live configuration was not replaced".format(stage, result),
                mismatch=mismatch, native_validation={"stage": stage, "exit_code": result})
        with open(path, "rb") as candidate:
            formatted = self._parse_config(candidate.read(), self._legacy_html_entities)
        self._validate_config(formatted)
        mismatch = self._config_difference(self.root, formatted.getroot())
        if mismatch is not None:
            raise PFSenseConfigError(
                "Native XML formatting changed configuration values at {0} ({1}); "
                "live configuration was not replaced".format(mismatch["path"], mismatch["reason"]),
                mismatch=mismatch)

    def get_interface_by_display_name(self, name):
        """ return interface_id by name """
        for interface in self.interfaces:
            descr_elt = interface.find("descr")
            if descr_elt is not None and descr_elt.text.strip().lower() == name.lower():
                return interface.tag
        return None

    def get_interface_by_port(self, name):
        """ return interface_id by port (os name) """
        for interface in self.interfaces:
            if interface.find("if").text.strip() == name:
                return interface.tag
        return None

    def get_interface_display_name(self, interface_id, return_none=False):
        """ return interface display name if found, otherwhise return the interface_id """
        if interface_id == "enc0":
            if return_none and not self.is_ipsec_enabled():
                return None
            return "IPsec"
        if interface_id == "openvpn":
            if return_none and not self.is_openvpn_enabled():
                return None
            return "OpenVPN"

        for interface in self.interfaces:
            if interface.tag == interface_id:
                descr_elt = interface.find("descr")
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
                return interface.find("if").text.strip()
        return None

    def get_interface_port_by_display_name(self, name):
        """ return interface port """
        for interface in self.interfaces:
            descr_elt = interface.find("descr")
            if descr_elt is not None and descr_elt.text.strip().lower() == name.lower():
                return interface.find("if").text.strip()
        return None

    def get_interfaces_networks(self):
        """ return interface local networks """
        ret = []
        for interface in self.interfaces:
            if interface.find("enable") is None:
                continue

            ipaddr_elt = interface.find("ipaddr")
            subnet_elt = interface.find("subnet")
            if ipaddr_elt is not None and subnet_elt is not None and ipaddr_elt.text is not None and subnet_elt.text is not None:
                ret.append("{0}/{1}".format(ipaddr_elt.text, subnet_elt.text))

            ipaddr_elt = interface.find("ipaddrv6")
            subnet_elt = interface.find("subnetv6")
            if ipaddr_elt is not None and subnet_elt is not None and ipaddr_elt.text is not None and subnet_elt.text is not None:
                ret.append("{0}/{1}".format(ipaddr_elt.text, subnet_elt.text))

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
            descr_elt = interface.find("descr")
            if descr_elt is not None:
                if descr_elt.text.strip().lower() == name.lower():
                    return True
        return False

    def is_interface_group(self, name):
        """ determines if arg is an interface group name or not """
        if self.ifgroups is not None:
            for interface in self.ifgroups:
                ifname_elt = interface.find("ifname")
                if ifname_elt is not None:
                    # ifgroup names appear to be case sensitive
                    if ifname_elt.text.strip() == name:
                        return True
        return False

    def parse_interface(self, interface, fail=True, with_virtual=True, with_gwgroup=False):
        """ validate param interface field """
        if with_virtual and (interface == "enc0" or interface.lower() == "ipsec") and self.is_ipsec_enabled():
            return "enc0"
        if with_virtual and (interface == "openvpn" or interface.lower() == "openvpn") and self.is_openvpn_enabled():
            return "openvpn"
        if with_gwgroup and self.is_gateway_group(interface):
            return interface

        if self.is_interface_display_name(interface):
            return self.get_interface_by_display_name(interface)
        elif self.is_interface_port(interface):
            return interface
        elif self.is_interface_group(interface):
            return interface

        if fail:
            self.module.fail_json(msg="%s is not a valid interface" % (interface))
        return None

    @staticmethod
    def is_ipv4_address(address):
        """ test if address is a valid ipv4 address """
        try:
            addr = ip_address(u"{0}".format(address))
            return isinstance(addr, IPv4Address)
        except ValueError:
            pass
        return False

    @staticmethod
    def is_ipv6_address(address):
        """ test if address is a valid ipv6 address """
        try:
            addr = ip_address(u"{0}".format(address))
            return isinstance(addr, IPv6Address)
        except ValueError:
            pass
        return False

    @staticmethod
    def is_ipv4_network(address, strict=True):
        """ test if address is a valid ipv4 network """
        try:
            addr = ip_network(u"{0}".format(address), strict=strict)
            return isinstance(addr, IPv4Network)
        except ValueError:
            pass
        return False

    @staticmethod
    def is_ipv6_network(address, strict=True):
        """ test if address is a valid ipv6 network """
        try:
            addr = ip_network(u"{0}".format(address), strict=strict)
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
            addr = ip_address(u"{0}".format(address))
        except ValueError:
            return False

        for network in networks:
            try:
                net = ip_network(u"{0}".format(network), strict=False)
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
            addr = ip_network(u"{0}".format(address), strict=strict)
            if strict or not returns_ip:
                return (str(addr.network_address), addr.prefixlen)
            else:
                # we parse the address with ipaddr just for type checking
                # but we use a regex to return the result as it dont kept the address bits
                group = re.match(r"(.*)/(.*)", address)
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
            addr = param.split(":", maxsplit=3)
            if len(addr) > 3:
                self.module.fail_json(msg="Cannot parse address %s" % (param))

        address = addr[0]

        ret = dict()
        # Check if the first character is "!"
        if address[0] == "!":
            # Invert the rule
            ret["not"] = None
            address = address[1:]

        if address == "NET" or address == "IP":
            interface = addr[1] if len(addr) > 1 else None
            ports = addr[2] if len(addr) > 2 else None
            if interface is None or interface == "":
                self.module.fail_json(msg="Cannot parse address %s" % (param))

            ret["network"] = self.parse_interface(interface)
            if address == "IP":
                ret["network"] += "ip"
        else:
            ports = addr[1] if len(addr) > 1 else None
            if address == "any":
                ret["any"] = None
            # rule with this firewall
            elif allow_self and address == "(self)":
                ret["network"] = "(self)"
            # rule with interface name (LAN, WAN...)
            elif self.is_interface_display_name(address):
                ret["network"] = self.get_interface_by_display_name(address)
            else:
                if not self.is_ip_or_alias(address):
                    vip_address = self.get_virtual_ip_address(address)
                    if vip_address is None:
                        self.module.fail_json(msg="Cannot parse address %s, not IP or alias" % (address))
                    address = vip_address
                ret["address"] = address

        if ports is not None:
            self.parse_port(ports, ret)
            msg = "the :ports syntax at end of addresses is deprecated and support will be removed soon. Please use source_port and destination_port options."
            self.module.warn(msg)

        return ret

    def parse_port(self, src_ports, ret):
        """ validate and parse port address field and set it in ret """
        ports = src_ports.split("-")
        if len(ports) > 2 or ports[0] is None or ports[0] == "" or len(ports) == 2 and (ports[1] is None or ports[1] == ""):
            self.module.fail_json(msg="Cannot parse port %s" % (src_ports))

        if not self.is_port_or_alias(ports[0]):
            self.module.fail_json(msg="Cannot parse port %s, not port number or alias" % (ports[0]))
        ret["port"] = ports[0]

        if len(ports) > 1:
            if not self.is_port_or_alias(ports[1]):
                self.module.fail_json(msg="Cannot parse port %s, not port number or alias" % (ports[1]))
            ret["port"] += "-" + ports[1]

    def check_name(self, name, objtype):
        """ check name validity """

        msg = None
        if len(name) >= 32 or len(re.findall(r"(^_*$|^\d*$|[^a-zA-Z0-9_])", name)) > 0:
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

        if ipprotocol == "inet":
            if ipv6 or not ipv4 and fail_ifnotip:
                self.module.fail_json(msg="{0} must use an IPv4 address".format(objtype))
        elif ipprotocol == "inet6":
            if ipv4 or not ipv6 and fail_ifnotip:
                self.module.fail_json(msg="{0} must use an IPv6 address".format(objtype))
        elif ipprotocol == "inet46":
            if ipv4 or ipv6:
                self.module.fail_json(msg="IPv4 and IPv6 addresses can not be used in objects that apply to both IPv4 and IPv6 (except within an alias).")

    def validate_openvpn_tunnel_network(self, network, ipproto):
        """ check openvpn tunnel network validity - based on pfSense's openvpn_validate_tunnel_network() """
        if network is not None and network != "":
            alias_elt = self.find_alias(network, aliastype="network")
            if alias_elt is not None:
                networks = alias_elt.find("address").text.split()
                if len(networks) > 1:
                    self.module.fail_json("The alias {0} contains more than one network".format(network))
                network = networks[0]

            if not self.is_ipv4_network(network, strict=False) and ipproto == "ipv4":
                self.module.fail_json("{0} is not a valid IPv4 network".format(network))
            if not self.is_ipv6_network(network, strict=False) and ipproto == "ipv6":
                self.module.fail_json("{0} is not a valid IPv6 network".format(network))
            return True

        return True

    def validate_string(self, name, objtype):
        """ check string validity - similar to pfSense's do_input_validate() """

        if len(re.findall(r"[\000-\010\013\014\016-\037]", name)) > 0:
            self.module.fail_json("The {0} name contains invalid characters.".format(objtype))

    @staticmethod
    def addr_normalize(addr):
        """ return address element formatted like module argument """
        address = ""
        ports = ""
        if "address" in addr:
            address = addr["address"]
        if "any" in addr:
            address = "any"
        if "network" in addr:
            address = "NET:%s" % addr["network"]
        if address == "":
            raise ValueError("UNKNOWN addr %s" % addr)
        if "port" in addr:
            ports = addr["port"]
        if "not" in addr:
            address = "!" + address
        return address, ports

    @staticmethod
    def new_element(tag, text="\n\t\t\t"):
        """ Create and return new XML configuration element  """
        elt = ET.Element(tag)
        # Attempt to preserve some of the formatting of pfSense's config.xml
        elt.text = text
        elt.tail = "\n\t\t"
        return elt

    def get_element(self, node, root_elt=None, create_node=False):
        """ return <node> configuration element """
        if root_elt is None:
            root_elt = self.root
        top_elt = root_elt
        for item in node.split("/"):
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

    def find_elt(self, node, search_text, search_field="descr", root_elt=None, multiple_ok=False):
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
                self.module.fail_json(msg="Found multiple elements for name {0}.".format(self.obj["name"]))
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
            if elt.tag == "phase1" and elt.find("disabled") is None:
                return True
        return False

    def is_openvpn_enabled(self):
        """ return True if openvpn is enabled """
        if self.openvpn is None:
            return False

        for elt in self.openvpn:
            if elt.tag == "openvpn-server" or elt.tag == "openvpn-client":
                return True
        return False

    def find_ipsec_phase1(self, field_value, field="descr"):
        """ return ipsec phase1 elt if found """
        for ipsec_elt in self.ipsec:
            if ipsec_elt.tag != "phase1":
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
        interface_elt = rule_elt.find("interface")
        floating_elt = rule_elt.find("floating")
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
            descr_elt = rule_elt.find("descr")
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
            self.debug.write("changed=%s key=%s this_elt=%s, sub=%d\n" % (changed, key, this_elt, sub))
            if this_elt is None:
                if isinstance(value, dict):
                    changed = True
                    self.debug.write("calling copy_dict_to_element()\n")
                    # Create a new element
                    new_elt = ET.Element(key)
                    new_elt.text = "\n%s" % ("\t" * (sub + 4))
                    new_elt.tail = "\n%s" % ("\t" * (sub + 2))
                    if prev_elt is not None:
                        prev_elt.tail = "\n%s" % ("\t" * (sub + 2))
                    prev_elt = new_elt
                    self.copy_dict_to_element(value, new_elt, sub=sub + 1, prev_elt=prev_elt)
                    top_elt.append(new_elt)
                elif isinstance(value, list):
                    if value:
                        changed = True
                        if prev_elt is not None:
                            prev_elt.tail = "\n%s" % ("\t" * (sub + 2))
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
                    new_elt.tail = "\n%s" % ("\t" * (sub + 2))
                    if prev_elt is not None:
                        prev_elt.tail = "\n%s" % ("\t" * (sub + 2))
                    prev_elt = new_elt
                    top_elt.append(new_elt)
                self.debug.write("changed=%s added key=%s value=%s tag=%s\n" % (changed, key, value, top_elt.tag))
            else:
                if isinstance(value, dict):
                    self.debug.write("calling copy_dict_to_element()\n")
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
                            if all_sub_elts[idx].text is None and item == "":
                                pass
                            elif all_sub_elts[idx].text != item:
                                all_sub_elts[idx].text = item
                                changed = True
                        elif self.copy_dict_to_element(item, all_sub_elts[idx], sub=sub + 1, prev_elt=prev_elt):
                            changed = True
                else:
                    # If this element previously held a dict/list (has children)
                    # but the new value is a scalar, remove stale children first.
                    # Without this, nested elements (e.g. <item> inside <aliases>)
                    # persist even when the parent is set to an empty string,
                    # causing data from one list entry to bleed into another.
                    # Note: ET.Element.clear() is not used here because it also
                    # resets .tail, which would corrupt pretty-print whitespace.
                    if len(this_elt) > 0:
                        self.debug.write("changed=%s replacing contents of %s\n" % (changed, key))
                        for child in list(this_elt):
                            this_elt.remove(child)
                        changed = True
                    if this_elt.text is None and value == "":
                        pass
                    elif this_elt.text != value:
                        self.debug.write("changed=%s replacing text of %s\n" % (changed, key))
                        this_elt.text = value
                        changed = True
                prev_elt = this_elt

        # Sub-elements must be completely described, so remove any missing elements
        if sub:
            for child_elt in list(top_elt):
                if child_elt.tag not in src:
                    changed = True
                    self.debug.write("changed=%s removed tag=%s\n" % (changed, child_elt.tag))
                    top_elt.remove(child_elt)

        if prev_elt is not None:
            prev_elt.tail = "\n%s" % ("\t" * (sub + 1))

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
                value = elt.text if elt.text is not None else ""

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
            return xml_find(elt, "refid").text
        else:
            return None

    def get_caref(self, name):
        """ get CA refid for name """
        # global is a special case
        if name == "global":
            return "global"
        # Otherwise search the ca elements
        return self.get_refid("ca", name)

    def get_certref(self, name):
        """ get Cert refid for name """
        return self.get_refid("cert", name)

    def get_crlref(self, name):
        """ get CRL refid for name """
        return self.get_refid("crl", name)

    @staticmethod
    def get_username():
        """ get username logged """
        username = pwd.getpwuid(os.getuid()).pw_name
        if os.environ.get("SUDO_USER"):
            username = os.environ.get("SUDO_USER")
        # sudo masks this
        sshclient = os.environ.get("SSH_CLIENT")
        if sshclient:
            username = username + "@" + sshclient
        return username

    def find_alias(self, name, aliastype=None):
        """ return alias named name, having type aliastype if specified """
        for alias in self.aliases:
            if xml_find(alias, "name").text == name and (aliastype is None or xml_find(alias, "type").text == aliastype):
                return alias
        return None

    def is_ip_or_alias(self, address):
        """ return True if address is an ip or an alias """
        # Is it an alias?
        if (self.find_alias(address, "host") is not None
                or self.find_alias(address, "network") is not None
                or self.find_alias(address, "urltable") is not None):
            return True

        # Is it an IP address or network?
        if self.is_ipv4_address(address) or self.is_ipv4_network(address) or self.is_ipv6_address(address) or self.is_ipv6_network(address):
            return True

        # None of the above
        return False

    def is_gateway_group(self, gwgroup):
        """ return True if gwgroup is a gateway group """
        return any(group.findtext("name") == gwgroup for group in self.root.findall("./gateways/gateway_group"))

    def is_port_or_alias(self, port):
        """ return True if port is a valid port number or an alias """
        if (self.find_alias(port, "port") is not None
                or self.find_alias(port, "urltable_ports") is not None):
            return True
        try:
            if int(port) > 0 and int(port) < 65536:
                return True
        except ValueError:
            pass
        return False

    def find_virtual_ip(self, value, fields=("descr", "subnet"), modes=None):
        """Find a VIP by the first matching field in lookup order."""
        if not value or self.virtualip is None:
            return None

        candidates = self.virtualip.findall("vip")
        if modes is not None:
            candidates = [vip for vip in candidates if vip.findtext("mode") in modes]
        for field in fields:
            matches = [vip for vip in candidates if vip.findtext(field) == value]
            if len(matches) > 1:
                self.module.fail_json(msg=f"Found multiple virtual IPs matching '{value}'. Use a unique description or address.")
            if matches:
                return matches[0]
        return None

    def get_virtual_ip_address(self, description):
        """Return the configured address for a VIP description."""
        vip = self.find_virtual_ip(description, fields=("descr",))
        if vip is None:
            return None
        address = vip.findtext("subnet")
        if address and (self.is_ipv4_address(address) or self.is_ipv6_address(address)):
            return address
        return None

    def get_virtual_ip_interface(self, value):
        """Return the pfSense interface ID for a VIP description or address."""
        vip = self.find_virtual_ip(value)
        uid = vip.findtext("uniqid") if vip is not None else None
        return "_vip" + uid if uid else None

    def resolve_openvpn_interface(self, value):
        """Resolve a VIP description to the web GUI's selector form, `_vip<uniqid>|<address>`.
        OpenVPN stores the two parts apart: use get_openvpn_bind to get them."""
        if not value or value in ("any", "lo0") or self.is_interface_port(value):
            return value
        if value.startswith("_vip") and "|" in value:
            return value

        vip = self.find_virtual_ip(value, fields=("descr",), modes=("carp", "ipalias"))
        if vip is not None and vip.findtext("uniqid") and vip.findtext("subnet") and not self.is_gateway_group(value):
            return "_vip{0}|{1}".format(vip.findtext("uniqid"), vip.findtext("subnet"))
        return value

    def get_openvpn_bind(self, value):
        """Return the interface and the address an OpenVPN instance binds to.
        As the web GUI does, a VIP is stored as its interface (_vip<uniqid>) and, apart, its address (ipaddr):
        openvpn.inc binds to ipaddr, and does not resolve an interface holding both."""
        interface, separator, address = self.resolve_openvpn_interface(value).partition("|")
        if not separator and interface.startswith("_vip"):
            # As for a description, only the VIPs the web GUI offers to OpenVPN
            vip = self.find_virtual_ip(interface[4:], fields=("uniqid",), modes=("carp", "ipalias"))
            address = vip.findtext("subnet", "") if vip is not None else ""
        return interface, address

    def find_queue(self, name, interface=None, enabled=False):
        """ return QOS queue if found """

        # iterate each interface
        for shaper_elt in self.shapers:
            if interface is not None:
                interface_elt = shaper_elt.find("interface")
                if interface_elt is None or interface_elt.text != interface:
                    continue

            if enabled:
                enabled_elt = shaper_elt.find("enabled")
                if enabled_elt is None or enabled_elt.text != "on":
                    continue

            # iterate each queue
            for queue_elt in shaper_elt.findall(".//queue"):
                name_elt = queue_elt.find("name")
                if name_elt is None or name_elt.text != name:
                    continue

                if enabled:
                    enabled_elt = queue_elt.find("enabled")
                    if enabled_elt is None or enabled_elt.text != "on":
                        continue

                # found it
                return queue_elt

        return None

    def find_limiter(self, name, enabled=False):
        """ return QOS limiter if found """

        # iterate each queue
        for queue_elt in self.dnshapers:
            if enabled:
                enabled_elt = queue_elt.find("enabled")
                if enabled_elt is None or enabled_elt.text != "on":
                    continue

            name_elt = queue_elt.find("name")
            if name_elt is None or name_elt.text != name:
                continue

            return queue_elt

        return None

    def find_vlan(self, interface, tag):
        """ return vlan elt if found """
        if self.vlans is None:
            self.vlans = self.get_element("vlans")

        if self.vlans is not None:
            for vlan in self.vlans:
                if xml_find(vlan, "if").text == interface and xml_find(vlan, "tag").text == tag:
                    return vlan

        return None

    def _create_gw_elt(self, name, interface_id, protocol):
        gw_elt = ET.Element("gateway_item")
        gw_elt.append(self.new_element("interface", interface_id))
        gw_elt.append(self.new_element("gateway", "dynamic"))
        gw_elt.append(self.new_element("name", name))
        gw_elt.append(self.new_element("weight", "1"))
        gw_elt.append(self.new_element("ipprotocol", protocol))
        gw_elt.append(self.new_element("descr", "Interface " + name + " Gateway"))
        return gw_elt

    def find_gateway_elt(self, name, interface=None, protocol=None, dhcp=False, vti=False):
        """ return gateway elt if found """
        for gw_elt in self.get_elements("gateways/gateway_item"):
            if protocol is not None and xml_find(gw_elt, "ipprotocol").text != protocol:
                continue

            if interface is not None and xml_find(gw_elt, "interface").text != interface:
                continue

            if xml_find(gw_elt, "name").text == name:
                return gw_elt

        for interface_elt in self.interfaces:
            descr_elt = interface_elt.find("descr")
            if descr_elt is None or descr_elt.text is None:
                continue

            if_elt = interface_elt.find("if")
            if if_elt is None or if_elt.text is None:
                continue

            descr_text = descr_elt.text.strip().upper()

            # todo: implement interface match with ipsec tunnels threw vtimaps
            if vti and (protocol is None or protocol == "inet") and if_elt.text.startswith("ipsec") and descr_text + "_VTIV4" == name:
                return self._create_gw_elt(name, interface_elt.tag, "inet")

            if vti and (protocol is None or protocol == "inet6") and if_elt.text.startswith("ipsec") and descr_text + "_VTIV6" == name:
                return self._create_gw_elt(name, interface_elt.tag, "inet6")

            if dhcp:
                ipaddr_elt = interface_elt.find("ipaddr")
                if (protocol is None or protocol == "inet") and ipaddr_elt is not None and ipaddr_elt.text == "dhcp" and descr_text + "_DHCP" == name:
                    return self._create_gw_elt(name, interface_elt.tag, "inet")

                ipaddr_elt = interface_elt.find("ipaddrv6")
                if (protocol is None or protocol == "inet6") and ipaddr_elt is not None and ipaddr_elt.text == "dhcp6" and descr_text + "_DHCP6" == name:
                    return self._create_gw_elt(name, interface_elt.tag, "inet6")

        return None

    def find_gateway_group_elt(self, name, protocol="inet"):
        """ return gateway_group elt if found """
        for gw_grp_elt in self.gateways:
            if gw_grp_elt.tag != "gateway_group":
                continue
            if xml_find(gw_grp_elt, "name").text != name:
                continue

            # check if protocol match
            match_protocol = True
            for gw_elt in gw_grp_elt:
                if gw_elt.tag != "item" or gw_elt.text is None:
                    continue

                items = gw_elt.text.split("|")
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

    def find_ca_elt(self, ca, search_field="descr"):
        """ return certificate authority elt if found """
        return self.find_elt("ca", ca, search_field)

    def find_cert_elt(self, cert, search_field="descr"):
        """ return certificate elt if found """
        return self.find_elt("cert", cert, search_field)

    def find_crl_elt(self, crl, search_field="descr"):
        """ return certificate revocation list elt if found """
        return self.find_elt("crl", crl, search_field)

    def find_schedule_elt(self, name):
        """ return schedule elt if found """
        return self.find_elt_xpath("./schedules/schedule[name='{0}']".format(name))

    @staticmethod
    def uniqid(prefix="", more_entropy=False):
        """ return an identifier based on time """
        if more_entropy:
            return prefix + "{0:x}{1:05x}{2:.8F}".format(int(time.time()), int(time.time() * 1000000) % 0x100000, random.random() * 10)

        return prefix + "{0:x}{1:05x}".format(int(time.time()), int(time.time() * 1000000) % 0x100000)

    def phpshell(self, command, debug=True):
        """ Run a command in the php developer shell """
        phpshell = "global $config;\n"
        if debug:
            phpshell = "global $debug;\n$debug = 1;\n"
        phpshell += command + "\nexec\nexit"
        # Dummy argument suppresses displaying help message
        return self.module.run_command("/usr/local/sbin/pfSsh.php dummy", data=phpshell)

    def php(self, command):
        """ Run a command in php and return the output """
        cmd = "<?php\n"
        cmd += command
        cmd += "\n?>\n"
        (dummy, stdout, stderr) = self.module.run_command("/usr/local/bin/php", data=cmd)
        # If /var/run/booting is in place, various requires will emit a "."
        (stdout, nsubs) = re.subn(r"^\.+", "", stdout)
        if nsubs > 0:
            self.module.warn("/var/run/booting appears to be present, confirm successful boot and remove if appropriate.")
        # TODO: check stderr for errors
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as e:
            self.module.fail_json(msg=f"{e}", cmd=cmd, stdout=stdout, stderr=stderr)
        return result

    def write_config(self, descr="Updated by ansible pfsense module"):
        """Validate and atomically commit a configuration snapshot."""
        revision = self.get_element("revision", create_node=True)
        self.get_element("time", revision, create_node=True).text = "%d" % time.time()
        revdescr = revision.find("description")
        if revdescr is None:
            revdescr = ET.Element("description")
            revision.append(revdescr)
        revdescr.text = descr
        username = self.get_username()
        self.get_element("username", revision, create_node=True).text = username
        committed = False
        try:
            self._validate_config(self.tree)
            serialized = self._serialize_config()
            validated = self._parse_config(serialized, self._legacy_html_entities)
            self._validate_config(validated)
            mismatch = self._config_difference(self.root, validated.getroot())
            if mismatch is not None:
                raise PFSenseConfigError(
                    "Configuration text changed during XML serialization at {0} ({1})".format(
                        mismatch["path"], mismatch["reason"]), mismatch=mismatch)

            with self._locked_config():
                with open(self.config, "rb") as source:
                    current = source.read()
                    metadata = os.fstat(source.fileno())
                if hashlib.sha256(current).digest() != self._config_digest:
                    raise PFSenseConfigError(
                        "Configuration changed since this module read it; "
                        "no config or backup was written. Rerun the task from a fresh read")

                # Keep one protected, byte-for-byte pre-change configuration.
                # Failure to persist the backup aborts before replacing config.
                self._atomic_replace(self.config + ".ansible.bak", current, metadata, 0o600)
                self._sync_config_directory()
                serialized = self._atomic_replace(self.config, serialized, metadata, stat.S_IMODE(metadata.st_mode),
                                                  validate=self._validate_native_config)
                committed = True
                self._config_digest = hashlib.sha256(serialized).digest()
                try:
                    try:
                        os.unlink(self.config_cache)
                    except OSError as error:
                        if error.errno != errno.ENOENT:
                            raise
                finally:
                    # Keep cache invalidation and durability inside the lock,
                    # even when reporting a failure after the atomic rename.
                    self._sync_config_directory()
        except (OSError, ValueError, UnicodeError, ET.ParseError, ExpatError, PFSenseConfigError) as error:
            details = {}
            if isinstance(error, PFSenseConfigError) and error.mismatch is not None:
                details["config_mismatch"] = error.mismatch
            if isinstance(error, PFSenseConfigError) and error.native_validation is not None:
                details["native_validation"] = error.native_validation
            self.module.fail_json(
                msg="{0}: {1}".format(
                    "Configuration was replaced, but finalization failed" if committed
                    else "Refusing to write pfSense configuration", error),
                changed=committed,
                backup_file=self.config + ".ansible.bak", **details)

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
        return len(version.split(".")[0]) == 1

    def is_version(self, version, or_more=True):
        """ check target pfSense version """
        if self.pfsense_version is None:
            pfsense_version = self.get_version()
            self.pfsense_version = []
            match = re.match(r"(\d+)\.(\d+)\.?(\d+)?", pfsense_version)
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
