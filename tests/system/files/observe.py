"""Read appliance state independently of the collection's module utilities."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


def read_pf_state(alias_name, rule_name):
    """Inspect root and anchor rulesets, retaining private table scope."""
    anchors = subprocess.run(['/sbin/pfctl', '-v', '-s', 'Anchors'],
                             capture_output=True, text=True, check=True)
    scopes = [''] + sorted(set(line.strip() for line in anchors.stdout.splitlines() if line.strip()))
    loaded_rules, rule_scopes, tables, table_errors = [], [], {}, {}
    for scope in scopes:
        command = ['/sbin/pfctl'] + (['-a', scope] if scope else [])
        loaded = subprocess.run(command + ['-sr'], capture_output=True, text=True, check=True)
        matches = [line.strip() for line in loaded.stdout.splitlines() if rule_name in line]
        if matches:
            loaded_rules.extend(matches)
            rule_scopes.append(scope)
        table = subprocess.run(command + ['-t', alias_name, '-T', 'show'],
                               capture_output=True, text=True, check=False)
        if table.returncode == 0:
            tables[scope] = sorted(line.strip() for line in table.stdout.splitlines() if line.strip())
        else:
            table_errors[scope or '/'] = table.stderr.strip()

    # A rule uses its anchor's private table, falling back to the root table.
    # Keep each scope separate: merging tables could conceal a stale private copy.
    rule_tables = {scope or '/': tables.get(scope, tables.get('')) for scope in rule_scopes}
    return {
        'loaded_rules': loaded_rules,
        'rule_anchors': [scope or '/' for scope in rule_scopes],
        'rule_tables': rule_tables,
        'tables': {scope or '/': entries for scope, entries in tables.items()},
        'table_errors': table_errors,
        'table_exists': bool(tables),
        'table_entries': sorted(set(entry for entries in tables.values() for entry in entries)),
    }


def observe(alias_name, rule_name):
    config = Path('/cf/conf/config.xml').read_bytes()
    root = ET.fromstring(config)
    aliases = [dict((child.tag, child.text or '') for child in alias)
               for alias in root.findall('aliases/alias')
               if alias.findtext('name') == alias_name]
    rules = [dict((key, rule.findtext(key)) for key in ('descr', 'type', 'interface', 'source/address'))
             for rule in root.findall('filter/rule')
             if rule.findtext('descr') == rule_name]
    cache = Path('/var/db/aliastables') / (alias_name + '.txt')
    state = {
        'config_sha256': hashlib.sha256(config).hexdigest(),
        'aliases': aliases,
        'rules': rules,
        'cache_entries': sorted(cache.read_text().split()) if cache.exists() else [],
        'filter_reload': read_reload_status(),
        'booting': Path('/var/run/booting').exists(),
    }
    state.update(read_pf_state(alias_name, rule_name))
    return state


def read_reload_status(path=Path('/var/run/filter_reload_status')):
    """Native progress is diagnostic; an old Done is not proof of this apply."""
    try:
        messages = path.read_text(errors='replace').splitlines()
        return {'mtime_ns': path.stat().st_mtime_ns,
                'last_message': messages[-1] if messages else '', 'messages': messages}
    except FileNotFoundError:
        return None
    except OSError as error:
        return {'error': str(error)}


def pf_converged(state, action, expected_entry=None):
    """A queued reload is complete only when the expected kernel state is visible."""
    if action == 'absent':
        return not state['loaded_rules']
    expected_entries = [expected_entry]
    return (bool(state['loaded_rules']) and
            all(line.startswith(action + ' ') for line in state['loaded_rules']) and
            state['table_exists'] and state['table_entries'] == expected_entries and
            bool(state['rule_tables']) and
            all(entries == expected_entries for entries in state['rule_tables'].values()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--alias', default='ci_urltable')
    parser.add_argument('--rule', default='CI URL table test')
    parser.add_argument('--expect-action', choices=('pass', 'block', 'absent'))
    parser.add_argument('--expect-entry')
    arguments = parser.parse_args()
    if arguments.expect_action in ('pass', 'block') and arguments.expect_entry is None:
        parser.error('--expect-entry is required when waiting for a pass/block rule')
    state = observe(arguments.alias, arguments.rule)
    print(json.dumps(state))
    if arguments.expect_action:
        sys.exit(0 if pf_converged(state, arguments.expect_action, arguments.expect_entry) else 1)
