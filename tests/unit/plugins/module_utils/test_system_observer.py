"""Regression tests for root and anchor-scoped appliance observations."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


CORE = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location('system_observer', CORE / 'tests/system/files/observe.py')
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)

RULE = 'pass in on vtnet1 from <ci_urltable> to any label "descr=CI URL table test"'


class TestSystemObserver(unittest.TestCase):
    def state(self, rules, tables):
        scopes = sorted(set(rules) | set(tables))

        def kernel(command, **kwargs):
            if command == ['/sbin/pfctl', '-v', '-s', 'Anchors']:
                output = ''.join('  ' + scope + '\n' for scope in scopes if scope)
                return subprocess.CompletedProcess(command, 0, output, '')
            scope = command[command.index('-a') + 1] if '-a' in command else ''
            if command[-1] == '-sr':
                return subprocess.CompletedProcess(command, 0, rules.get(scope, ''), '')
            if command[-4:] == ['-t', 'ci_urltable', '-T', 'show']:
                if scope in tables:
                    output = ''.join('   ' + entry + '\n' for entry in tables[scope])
                    return subprocess.CompletedProcess(command, 0, output, '')
                return subprocess.CompletedProcess(command, 1, '', 'Table does not exist')
            raise AssertionError('Unexpected kernel query: ' + str(command))

        with patch.object(observer.subprocess, 'run', side_effect=kernel):
            return observer.read_pf_state('ci_urltable', 'CI URL table test')

    def test_legacy_root_rules_and_table(self):
        state = self.state({'': RULE}, {'': ['192.0.2.10']})
        self.assertEqual(state['loaded_rules'], [RULE])
        self.assertEqual(state['rule_tables'], {'/': ['192.0.2.10']})

    def test_nested_rule_and_private_table_without_root_table(self):
        state = self.state({'': 'anchor "userrules/*" all', 'userrules/123': '  ' + RULE},
                           {'userrules/123': ['192.0.2.10']})
        self.assertEqual(state['loaded_rules'], [RULE])
        self.assertEqual(state['rule_anchors'], ['userrules/123'])
        self.assertTrue(state['table_exists'])
        self.assertEqual(state['rule_tables'], {'userrules/123': ['192.0.2.10']})

    def test_anchor_rule_falls_back_to_global_table(self):
        state = self.state({'userrules/123': RULE}, {'': ['192.0.2.10']})
        self.assertEqual(state['rule_tables'], {'userrules/123': ['192.0.2.10']})

    def test_private_table_shadows_a_different_global_table(self):
        state = self.state({'userrules/123': RULE},
                           {'': ['198.51.100.20'], 'userrules/123': ['192.0.2.10']})
        self.assertEqual(state['rule_tables'], {'userrules/123': ['192.0.2.10']})

    def test_unrelated_table_cannot_satisfy_a_rule_in_another_anchor(self):
        state = self.state({'userrules/123': RULE}, {'unrelated': ['192.0.2.10']})
        self.assertEqual(state['rule_tables'], {'userrules/123': None})

    def test_missing_rule_and_table_remain_missing(self):
        state = self.state({'': 'anchor "userrules/*" all'}, {})
        self.assertEqual(state['loaded_rules'], [])
        self.assertEqual(state['rule_tables'], {})
        self.assertFalse(state['table_exists'])

    def test_waits_until_rule_and_table_both_reach_requested_state(self):
        before = self.state({'': ''}, {})
        rule_only = self.state({'': RULE}, {})
        ready = self.state({'': RULE}, {'': ['192.0.2.10']})
        self.assertFalse(observer.pf_converged(before, 'pass', '192.0.2.10'))
        self.assertFalse(observer.pf_converged(rule_only, 'pass', '192.0.2.10'))
        self.assertTrue(observer.pf_converged(ready, 'pass', '192.0.2.10'))

    def test_waits_for_changed_table_contents(self):
        old = self.state({'': RULE}, {'': ['192.0.2.10']})
        new = self.state({'': RULE}, {'': ['198.51.100.20']})
        self.assertFalse(observer.pf_converged(old, 'pass', '198.51.100.20'))
        self.assertTrue(observer.pf_converged(new, 'pass', '198.51.100.20'))

    def test_waits_for_rule_action_change(self):
        old = self.state({'': RULE}, {'': ['192.0.2.10']})
        new = self.state({'': RULE.replace('pass ', 'block ', 1)}, {'': ['192.0.2.10']})
        self.assertFalse(observer.pf_converged(old, 'block', '192.0.2.10'))
        self.assertTrue(observer.pf_converged(new, 'block', '192.0.2.10'))

    def test_waits_for_deletion_to_reach_the_kernel(self):
        old = self.state({'': RULE}, {'': ['192.0.2.10']})
        deleted = self.state({'': ''}, {})
        self.assertFalse(observer.pf_converged(old, 'absent'))
        self.assertTrue(observer.pf_converged(deleted, 'absent'))

    def test_old_native_done_does_not_satisfy_a_pending_apply(self):
        state = self.state({'': ''}, {})
        state['filter_reload'] = {'last_message': 'Done', 'messages': ['Initializing', 'Done']}
        self.assertFalse(observer.pf_converged(state, 'pass', '192.0.2.10'))


if __name__ == '__main__':
    unittest.main()
