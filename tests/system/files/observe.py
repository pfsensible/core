"""Read appliance state independently of the collection's module utilities."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import argparse
import hashlib
from ipaddress import ip_address, ip_interface
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


def pf_scopes():
    anchors = subprocess.run(["/sbin/pfctl", "-v", "-s", "Anchors"],
                             capture_output=True, text=True, check=True)
    return [""] + sorted(set(line.strip() for line in anchors.stdout.splitlines() if line.strip()))


def read_pf_state(alias_name, rule_name):
    """Inspect root and anchor rulesets, retaining private table scope."""
    loaded_rules, rule_scopes, tables, table_errors = [], [], {}, {}
    for scope in pf_scopes():
        command = ["/sbin/pfctl"] + (["-a", scope] if scope else [])
        loaded = subprocess.run(command + ["-sr"], capture_output=True, text=True, check=True)
        matches = [line.strip() for line in loaded.stdout.splitlines() if rule_name in line]
        if matches:
            loaded_rules.extend(matches)
            rule_scopes.append(scope)
        table = subprocess.run(command + ["-t", alias_name, "-T", "show"],
                               capture_output=True, text=True, check=False)
        if table.returncode == 0:
            tables[scope] = sorted(line.strip() for line in table.stdout.splitlines() if line.strip())
        else:
            table_errors[scope or "/"] = table.stderr.strip()

    # A rule uses its anchor's private table, falling back to the root table.
    # Keep each scope separate: merging tables could conceal a stale private copy.
    rule_tables = {scope or "/": tables.get(scope, tables.get("")) for scope in rule_scopes}
    return {
        "loaded_rules": loaded_rules,
        "rule_anchors": [scope or "/" for scope in rule_scopes],
        "rule_tables": rule_tables,
        "tables": {scope or "/": entries for scope, entries in tables.items()},
        "table_errors": table_errors,
        "table_exists": bool(tables),
        "table_entries": sorted(set(entry for entries in tables.values() for entry in entries)),
    }


def observe_nat(rule_name, target):
    """Read saved NAT and associated filter rules and their live PF entries."""
    config = Path("/cf/conf/config.xml").read_bytes()
    root = ET.fromstring(config)
    filter_name = "NAT " + rule_name
    match_fields = ("interface", "protocol", "source/address", "source/port", "destination/port", "associated-rule-id")
    redirects = []
    filters = []
    for scope in pf_scopes():
        command = ["/sbin/pfctl", "-P"] + (["-a", scope] if scope else [])
        nat = subprocess.run(command + ["-sn"], capture_output=True, text=True, check=True)
        rules = subprocess.run(command + ["-sr"], capture_output=True, text=True, check=True)
        redirects.extend(line.strip() for line in nat.stdout.splitlines()
                         if re.search(r"^\s*rdr\b.* -> " + re.escape(target) + r"(?=\s|$)", line))
        filters.extend(line.strip() for line in rules.stdout.splitlines() if filter_name in line)
    return {
        "config_sha256": hashlib.sha256(config).hexdigest(),
        "nat_rules": [{field: rule.findtext(field) for field in match_fields + ("destination/network", "target", "local-port")}
                      for rule in root.findall("nat/rule") if rule.findtext("descr") == rule_name],
        "filter_rules": [{field: rule.findtext(field) for field in match_fields + ("destination/address", "type")}
                         for rule in root.findall("filter/rule") if rule.findtext("descr") == filter_name],
        "redirects": redirects,
        "filters": filters,
        "filter_reload": read_reload_status(),
    }


def observe_vip(address):
    """Read the saved entry, interface addresses, and Proxy ARP registrations."""
    vip = ip_interface(address)
    config = Path("/cf/conf/config.xml").read_bytes()
    root = ET.fromstring(config)
    devices = []
    device = None
    interfaces = subprocess.run(["/sbin/ifconfig", "-a"], capture_output=True, text=True, check=True)
    for line in interfaces.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        if not line[0].isspace():
            device = fields[0].rstrip(":")
        elif fields[0] in ("inet", "inet6") and ip_address(fields[1].split("%")[0]) == vip.ip:
            vhid = fields[fields.index("vhid") + 1] if "vhid" in fields else None
            devices.append({"interface": device, "vhid": vhid})

    proxy_interfaces = []
    processes = subprocess.run(["/bin/ps", "-axww", "-o", "command="], capture_output=True, text=True, check=True)
    for line in processes.stdout.splitlines():
        fields = line.split()
        if fields and Path(fields[0]).name == "choparp" and str(vip) in fields and "auto" in fields:
            proxy_interfaces.append(fields[fields.index("auto") - 1])

    fields = ("mode", "type", "subnet_bits", "interface", "descr", "vhid")
    return {
        "config_sha256": hashlib.sha256(config).hexdigest(),
        "vips": [{field: entry.findtext(field) for field in fields} for entry in root.findall("virtualip/vip")
                 if entry.findtext("subnet") == str(vip.ip)],
        "devices": devices,
        "proxy_interfaces": sorted(proxy_interfaces),
    }


def nat_converged(state, ports=None):
    """Check source, incoming destination, and translated ports in live PF."""
    redirects, filters = state["redirects"], state["filters"]
    if ports is None:
        return not redirects and not filters
    source, destination, target = map(re.escape, ports)
    # PF prints equality for matched ports and a plain port for translation.
    redirect = rf"^rdr\b.*\bfrom .+ port = {source} to .+ port = {destination} -> \S+ port {target}(?=\s|$)"
    rule = rf"^pass\b.*\bfrom .+ port = {source} to .+ port = {target}(?=\s|$)"
    return (len(redirects) == len(filters) == 1
            and re.search(redirect, redirects[0]) is not None and re.search(rule, filters[0]) is not None)


def observe(alias_name, rule_name):
    config = Path("/cf/conf/config.xml").read_bytes()
    root = ET.fromstring(config)
    aliases = [dict((child.tag, child.text or "") for child in alias)
               for alias in root.findall("aliases/alias")
               if alias.findtext("name") == alias_name]
    rules = [dict((key, rule.findtext(key)) for key in ("descr", "type", "interface", "source/address"))
             for rule in root.findall("filter/rule")
             if rule.findtext("descr") == rule_name]
    cache = Path("/var/db/aliastables") / (alias_name + ".txt")
    state = {
        "config_sha256": hashlib.sha256(config).hexdigest(),
        "aliases": aliases,
        "rules": rules,
        "cache_entries": sorted(cache.read_text().split()) if cache.exists() else [],
        "filter_reload": read_reload_status(),
        "booting": Path("/var/run/booting").exists(),
    }
    state.update(read_pf_state(alias_name, rule_name))
    return state


def read_reload_status(path=Path("/var/run/filter_reload_status")):
    """Native progress is diagnostic; an old Done is not proof of this apply."""
    try:
        messages = path.read_text(errors="replace").splitlines()
        return {"mtime_ns": path.stat().st_mtime_ns,
                "last_message": messages[-1] if messages else "", "messages": messages}
    except FileNotFoundError:
        return None
    except OSError as error:
        return {"error": str(error)}


def pf_converged(state, action, expected_entry=None):
    """A queued reload is complete only when the expected kernel state is visible."""
    if action == "absent":
        return not state["loaded_rules"]
    expected_entries = [expected_entry]
    return (bool(state["loaded_rules"]) and
            all(line.startswith(action + " ") for line in state["loaded_rules"]) and
            state["table_exists"] and state["table_entries"] == expected_entries and
            bool(state["rule_tables"]) and
            all(entries == expected_entries for entries in state["rule_tables"].values()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alias", default="ci_urltable")
    parser.add_argument("--rule", default="CI URL table test")
    parser.add_argument("--expect-action", choices=("pass", "block", "absent"))
    parser.add_argument("--expect-entry")
    parser.add_argument("--nat-rule")
    parser.add_argument("--nat-target")
    parser.add_argument("--vip-address")
    nat_expectation = parser.add_mutually_exclusive_group()
    nat_expectation.add_argument("--expect-nat-ports", nargs=3, metavar=("SOURCE", "DESTINATION", "TARGET"))
    nat_expectation.add_argument("--expect-nat-absent", action="store_true")
    arguments = parser.parse_args()
    if arguments.vip_address is not None:
        print(json.dumps(observe_vip(arguments.vip_address)))
        sys.exit(0)
    if arguments.nat_rule is not None:
        if arguments.nat_target is None:
            parser.error("--nat-target is required with --nat-rule")
        state = observe_nat(arguments.nat_rule, arguments.nat_target)
        print(json.dumps(state))
        if arguments.expect_nat_ports or arguments.expect_nat_absent:
            sys.exit(0 if nat_converged(state, arguments.expect_nat_ports) else 1)
        sys.exit(0)
    if arguments.expect_action in ("pass", "block") and arguments.expect_entry is None:
        parser.error("--expect-entry is required when waiting for a pass/block rule")
    state = observe(arguments.alias, arguments.rule)
    print(json.dumps(state))
    if arguments.expect_action:
        sys.exit(0 if pf_converged(state, arguments.expect_action, arguments.expect_entry) else 1)
