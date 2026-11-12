"""awg-cascade-rules (cascade_rules.py), contracts.md sections 2.1, 2.2 and 3."""
import contextlib
import io
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import load_rules  # noqa: E402

rules = load_rules()

HEADER = '# Managed by amneziawg-cascade. Format: <client address> <routing table>\n'
NET = ipaddress.ip_network('10.2.0.0/24')
TABLES = {10010, 10020}

SHOW = ('0:\tfrom all lookup local\n'
        '10000:\tfrom 10.2.0.0/24 iif awg0 fwmark 0x64 lookup 10011\n'
        '10005:\tfrom 10.2.0.2 iif awg0 lookup 10010\n'
        '10005:\tfrom 10.2.0.9 iif awg0 [detached] lookup 10020\n'
        '10005:\tfrom 10.2.0.0/24 iif awg0 lookup 10010\n'
        '10010:\tfrom 10.2.0.0/24 iif awg0 lookup 10019\n'
        '32766:\tfrom all lookup main\n')

ROUTES = [('-4', 'route', 'replace', 'unreachable', 'default', 'metric', '32760', 'table', t)
          for t in ('10019', '10010', '10020')]
SHOW_CMD = ('-4', '-N', 'rule', 'show')


def v2_settings(**over):
    doc = {'interface': 'awg0', 'endpoint': '203.0.113.10', 'dns': '1.1.1.1',
           'client_network': '10.2.0.0/24', 'default_hub': 'hub_de', 'stub_table': 10019,
           'hubs': {'hub_de': {'index': 1, 'interface': 'awg1', 'table': 10010},
                    'hub_us': {'index': 2, 'interface': 'awghub2', 'table': 10020}}}
    doc.update(over)
    return doc


def add_cmd(addr, table, iface='awg0'):
    return ('-4', 'rule', 'add', 'from', f'{addr}/32', 'iif', iface, 'priority', '10005',
            'lookup', str(table))


def del_cmd(src, table, iface='awg0'):
    return ('-4', 'rule', 'del', 'from', src, 'iif', iface, 'priority', '10005', 'lookup',
            str(table))


class RulesCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.calls = []
        self.show_output = ''
        self.fail_on = None   # predicate(args) -> exception or None
        patcher = patch.object(rules, 'ip', side_effect=self.fake_ip)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_ip(self, *args):
        self.calls.append(tuple(args))
        if self.fail_on is not None:
            exc = self.fail_on(tuple(args))
            if exc is not None:
                raise exc
        if tuple(args) == SHOW_CMD:
            return self.show_output
        return ''

    def write_settings(self, doc=None):
        (self.base / 'cascade-settings.json').write_bytes(
            json.dumps(v2_settings() if doc is None else doc).encode('utf-8'))

    def write_bindings(self, text):
        (self.base / 'cascade-bindings.list').write_bytes(text.encode('utf-8'))

    def prepare(self, bindings='10.2.0.2 10010\n10.2.0.3 10020\n10.2.0.4 10010\n', show=SHOW):
        self.write_settings()
        self.write_bindings(HEADER + bindings)
        self.show_output = show

    def run_main(self, argv=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rules.main(['--config-dir', str(self.base)] if argv is None else argv)
        return code, out.getvalue(), err.getvalue()

    def assertStateError(self, code_expected=3):
        code, out, err = self.run_main()
        self.assertEqual(code_expected, code, err)
        self.assertEqual('', out)
        self.assertTrue(err.startswith('Error: '), err)
        self.assertEqual(1, len(err.strip().splitlines()), err)
        self.assertNotIn('Traceback', err)
        return err


class ConstantsTest(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(10005, rules.PRIORITY)
        self.assertEqual(30.0, rules.LOCK_TIMEOUT)


class ParseBindingsTest(unittest.TestCase):
    def parse(self, text, network=NET, tables=TABLES):
        return rules.parse_bindings(text, network, tables)

    def test_example(self):
        self.assertEqual({'10.2.0.3': 10020, '10.2.0.2': 10010},
                         self.parse(HEADER + '10.2.0.3 10020\n10.2.0.2 10010\n'))

    def test_empty_and_comment_only_are_valid(self):
        self.assertEqual({}, self.parse(''))
        self.assertEqual({}, self.parse(HEADER))
        self.assertEqual({}, self.parse('# a\n\n# b\n'))

    def test_no_trailing_newline_and_boundary_octets(self):
        self.assertEqual({'10.2.0.2': 10010, '10.2.0.254': 10020},
                         self.parse('10.2.0.2 10010\n10.2.0.254 10020'))

    def test_corrupted_inputs(self):
        bad = ['10.2.0.2 10030\n', '10.2.0.2  10010\n', '10.2.0.2 10010\r\n',
               '10.3.0.2 10010\n', '10.2.0.1 10010\n', '10.2.0.255 10010\n',
               '10.2.0.02 10010\n', '10.2.0.2\n', '10.2.0.2 10010\n10.2.0.2 10010\n',
               ' 10.2.0.2 10010\n', '10.2.0.2 10010 \n', '10.2.0.2 10010\n10.2.0.2 10020\n',
               '10.2.0.2 abc\n', '10.2.0.300 10010\n', '10.2.0.2 10010 extra\n',
               '10.2.0.0 10010\n', '10.2.0 10010\n', '\t10.2.0.2 10010\n', 'garbage\n',
               '10.2.0.2\t10010\n', '10.2.0.2 +10010\n']
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(rules.RulesStateError):
                    self.parse(text)

    def test_comment_with_crlf_is_not_data(self):
        with self.assertRaises(rules.RulesStateError):
            self.parse('10.2.0.2 10010\r\n')

    def test_other_network(self):
        net = ipaddress.ip_network('10.9.1.0/24')
        self.assertEqual({'10.9.1.5': 10010}, self.parse('10.9.1.5 10010\n', network=net))
        with self.assertRaises(rules.RulesStateError):
            self.parse('10.2.0.5 10010\n', network=net)


class ParseRulesTest(unittest.TestCase):
    def test_example(self):
        self.assertEqual([('10.2.0.2/32', 'awg0', '10010'), ('10.2.0.9/32', 'awg0', '10020'),
                          ('10.2.0.0/24', 'awg0', '10010')], rules.parse_rules(SHOW))

    def test_all_source(self):
        self.assertEqual([('all', 'awg0', '10010')],
                         rules.parse_rules('10005:\tfrom all iif awg0 lookup 10010\n'))

    def test_empty_output(self):
        self.assertEqual([], rules.parse_rules(''))

    def test_other_priorities_ignored_even_if_odd(self):
        self.assertEqual([], rules.parse_rules('10006:\tgarbage here\n0:\tfrom all lookup local\n'))

    def test_explicit_prefix_kept(self):
        self.assertEqual([('10.2.0.2/32', 'awg0', '10010')],
                         rules.parse_rules('10005:\tfrom 10.2.0.2/32 iif awg0 lookup 10010\n'))

    def test_unparsable_rules(self):
        bad = ['10005:\tfrom 10.2.0.2 lookup 10010\n',
               '10005:\tfrom 10.2.0.2 iif awg0 fwmark 0x1 lookup 10010\n',
               '10005:\tfrom 10.2.0.2 iif awg0\n',
               '10005:\tsomething else\n']
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(rules.RulesApplyError):
                    rules.parse_rules(text)

    def test_order_follows_output(self):
        text = ('10005:\tfrom 10.2.0.9 iif awg0 lookup 10010\n'
                '10005:\tfrom 10.2.0.3 iif awg0 lookup 10010\n')
        self.assertEqual(['10.2.0.9/32', '10.2.0.3/32'], [r[0] for r in rules.parse_rules(text)])


class SyncTest(RulesCase):
    def test_full_run_exact_call_sequence(self):
        self.prepare()
        self.assertEqual((2, 2), rules.sync(self.base))
        self.assertEqual(ROUTES + [SHOW_CMD, add_cmd('10.2.0.3', 10020), add_cmd('10.2.0.4', 10010),
                                   del_cmd('10.2.0.9/32', 10020), del_cmd('10.2.0.0/24', 10010)],
                         self.calls)

    def test_idempotent_when_state_matches(self):
        show = ('0:\tfrom all lookup local\n'
                '10005:\tfrom 10.2.0.2 iif awg0 lookup 10010\n'
                '10005:\tfrom 10.2.0.3 iif awg0 lookup 10020\n'
                '10005:\tfrom 10.2.0.4 iif awg0 lookup 10010\n')
        self.prepare(show=show)
        self.assertEqual((0, 0), rules.sync(self.base))
        self.assertEqual(ROUTES + [SHOW_CMD], self.calls)

    def test_second_run_after_applying_changes_is_noop(self):
        self.prepare()
        rules.sync(self.base)
        self.calls.clear()
        self.show_output = ('10005:\tfrom 10.2.0.2 iif awg0 lookup 10010\n'
                            '10005:\tfrom 10.2.0.3 iif awg0 lookup 10020\n'
                            '10005:\tfrom 10.2.0.4 iif awg0 lookup 10010\n')
        self.assertEqual((0, 0), rules.sync(self.base))
        self.assertEqual(ROUTES + [SHOW_CMD], self.calls)

    def test_unreachable_tables_stub_first_then_hubs_ascending(self):
        doc = v2_settings(hubs={'hub_de': {'index': 1, 'interface': 'awg1', 'table': 10020},
                                'hub_us': {'index': 2, 'interface': 'awghub2', 'table': 10010}})
        self.write_settings(doc)
        self.write_bindings(HEADER)
        rules.sync(self.base)
        tables = [c[-1] for c in self.calls if c[1] == 'route']
        self.assertEqual(['10019', '10010', '10020'], tables)

    def test_all_route_blocks_precede_show_and_rule_changes(self):
        self.prepare()
        rules.sync(self.base)
        kinds = [c[1] if c != SHOW_CMD else 'show' for c in self.calls]
        self.assertEqual(['route'] * 3 + ['show'] + ['rule'] * 4, kinds)

    def test_adds_sorted_numerically_by_address(self):
        self.prepare(bindings='10.2.0.10 10010\n10.2.0.9 10010\n10.2.0.100 10020\n', show='')
        rules.sync(self.base)
        adds = [c[4] for c in self.calls if c[1:3] == ('rule', 'add')]
        self.assertEqual(['10.2.0.9/32', '10.2.0.10/32', '10.2.0.100/32'], adds)

    def test_all_adds_precede_all_deletes(self):
        show = ('10005:\tfrom 10.2.0.50 iif awg0 lookup 10010\n'
                '10005:\tfrom 10.2.0.51 iif awg0 lookup 10010\n')
        self.prepare(show=show)
        rules.sync(self.base)
        ops = [c[2] for c in self.calls if c[1] == 'rule' and c[2] in ('add', 'del')]
        self.assertEqual(['add'] * 3 + ['del'] * 2, ops)

    def test_duplicate_rules_second_is_deleted(self):
        show = ('10005:\tfrom 10.2.0.2 iif awg0 lookup 10010\n'
                '10005:\tfrom 10.2.0.2 iif awg0 lookup 10010\n')
        self.prepare(bindings='10.2.0.2 10010\n', show=show)
        self.assertEqual((0, 1), rules.sync(self.base))
        self.assertEqual(del_cmd('10.2.0.2/32', 10010), self.calls[-1])

    def test_wrong_table_is_replaced(self):
        show = '10005:\tfrom 10.2.0.2 iif awg0 lookup 10020\n'
        self.prepare(bindings='10.2.0.2 10010\n', show=show)
        self.assertEqual((1, 1), rules.sync(self.base))
        self.assertEqual([add_cmd('10.2.0.2', 10010), del_cmd('10.2.0.2/32', 10020)],
                         self.calls[-2:])

    def test_wrong_interface_is_replaced(self):
        show = '10005:\tfrom 10.2.0.2 iif awg9 lookup 10010\n'
        self.prepare(bindings='10.2.0.2 10010\n', show=show)
        self.assertEqual((1, 1), rules.sync(self.base))
        self.assertEqual([add_cmd('10.2.0.2', 10010), del_cmd('10.2.0.2/32', 10010, 'awg9')],
                         self.calls[-2:])

    def test_from_all_rule_is_deleted(self):
        self.prepare(bindings='', show='10005:\tfrom all iif awg0 lookup 10010\n')
        self.assertEqual((0, 1), rules.sync(self.base))
        self.assertEqual(del_cmd('all', 10010), self.calls[-1])

    def test_empty_bindings_removes_every_rule(self):
        self.prepare(bindings='', show=SHOW)
        self.assertEqual((0, 3), rules.sync(self.base))

    def test_uses_interface_from_settings(self):
        self.write_settings(v2_settings(interface='wg9'))
        self.write_bindings(HEADER + '10.2.0.2 10010\n')
        rules.sync(self.base)
        self.assertEqual(add_cmd('10.2.0.2', 10010, 'wg9'), self.calls[-1])

    def test_unparsable_rule_stops_before_changes(self):
        self.prepare(show='10005:\tfrom 10.2.0.2 lookup 10010\n')
        with self.assertRaises(rules.RulesApplyError):
            rules.sync(self.base)
        self.assertEqual(ROUTES + [SHOW_CMD], self.calls)

    def test_ip_failure_raises_apply_error_and_stops(self):
        self.prepare()
        self.fail_on = lambda a: (subprocess.CalledProcessError(2, ['ip', *a])
                                  if a[1:3] == ('rule', 'add') and a[4] == '10.2.0.3/32' else None)
        with self.assertRaises(rules.RulesApplyError) as cm:
            rules.sync(self.base)
        self.assertIsInstance(cm.exception.__cause__, subprocess.CalledProcessError)
        self.assertNotIn(add_cmd('10.2.0.4', 10010), self.calls)
        self.assertFalse([c for c in self.calls if c[1:3] == ('rule', 'del')])

    def test_oserror_from_ip_raises_apply_error(self):
        self.prepare()
        self.fail_on = lambda a: FileNotFoundError('ip')
        with self.assertRaises(rules.RulesApplyError):
            rules.sync(self.base)
        self.assertEqual(1, len(self.calls))

    def test_route_failure_stops_everything(self):
        self.prepare()
        self.fail_on = lambda a: (subprocess.CalledProcessError(1, ['ip'])
                                  if a[-1] == '10010' and a[1] == 'route' else None)
        with self.assertRaises(rules.RulesApplyError):
            rules.sync(self.base)
        self.assertNotIn(SHOW_CMD, self.calls)

    def test_state_errors_do_not_call_ip(self):
        cases = {}
        cases['no settings'] = lambda: (self.write_bindings(HEADER))
        cases['no bindings'] = lambda: self.write_settings()
        cases['legacy settings'] = lambda: (
            self.write_settings({'interface': 'awg0', 'endpoint': 'x', 'dns': 'y'}),
            self.write_bindings(HEADER))
        cases['bad json'] = lambda: (
            (self.base / 'cascade-settings.json').write_bytes(b'{not json'),
            self.write_bindings(HEADER))
        cases['settings not utf8'] = lambda: (
            (self.base / 'cascade-settings.json').write_bytes(b'\xff\xfe\x00'),
            self.write_bindings(HEADER))
        cases['bindings not utf8'] = lambda: (
            self.write_settings(), (self.base / 'cascade-bindings.list').write_bytes(b'\xff\xfe'))
        cases['bindings corrupted'] = lambda: (
            self.write_settings(), self.write_bindings(HEADER + '10.2.0.2 99999\n'))
        cases['bindings crlf'] = lambda: (
            self.write_settings(), self.write_bindings('10.2.0.2 10010\r\n'))
        cases['bindings is a directory'] = lambda: (
            self.write_settings(), (self.base / 'cascade-bindings.list').mkdir())
        for name, setup in cases.items():
            with self.subTest(case=name):
                for child in self.base.iterdir():
                    if child.is_dir():
                        child.rmdir()
                    else:
                        child.unlink()
                self.calls.clear()
                setup()
                with self.assertRaises(rules.RulesStateError):
                    rules.sync(self.base)
                self.assertEqual([], self.calls)

    def test_invalid_v2_settings_are_state_errors(self):
        bad = {
            'bad interface': v2_settings(interface='bad name'),
            'interface not str': v2_settings(interface=5),
            'empty hubs': v2_settings(hubs={}),
            'hubs not object': v2_settings(hubs=[]),
            'hub value not object': v2_settings(hubs={'hub_de': 5}),
            'table is bool': v2_settings(hubs={'hub_de': {'index': 1, 'interface': 'awg1',
                                                          'table': True}}),
            'table is str': v2_settings(hubs={'hub_de': {'index': 1, 'interface': 'awg1',
                                                         'table': '10010'}}),
            'no table': v2_settings(hubs={'hub_de': {'index': 1, 'interface': 'awg1'}}),
            'default_hub unknown': v2_settings(default_hub='hub_fr'),
            'network not /24': v2_settings(client_network='10.2.0.0/16'),
            'network not canonical': v2_settings(client_network='10.2.0.5/24'),
            'network garbage': v2_settings(client_network='nope'),
            'stub is bool': v2_settings(stub_table=True),
            'stub is str': v2_settings(stub_table='10019'),
            'stub equals hub table': v2_settings(stub_table=10010),
        }
        for name, doc in bad.items():
            with self.subTest(case=name):
                self.calls.clear()
                self.write_settings(doc)
                self.write_bindings(HEADER)
                with self.assertRaises(rules.RulesStateError):
                    rules.sync(self.base)
                self.assertEqual([], self.calls)

    def test_missing_keys_in_v2_settings_are_state_errors(self):
        for key in ('client_network', 'default_hub', 'stub_table', 'interface'):
            with self.subTest(missing=key):
                doc = v2_settings()
                del doc[key]
                self.write_settings(doc)
                self.write_bindings(HEADER)
                with self.assertRaises(rules.RulesStateError):
                    rules.sync(self.base)
                self.assertEqual([], self.calls)

    def test_non_string_default_hub_is_state_error(self):
        for value in (['hub_de'], {'hub_de': 1}, 5, None, True):
            with self.subTest(default_hub=value):
                self.calls.clear()
                self.write_settings(v2_settings(default_hub=value))
                self.write_bindings(HEADER)
                code, out, err = self.run_main()
                self.assertEqual(3, code, err)
                self.assertEqual('', out)
                self.assertTrue(err.startswith('Error: '), err)
                self.assertEqual(1, len(err.strip().splitlines()))
                self.assertNotIn('Traceback', err)
                self.assertEqual([], self.calls)

    def test_other_wrong_types_in_settings_are_state_errors(self):
        bad = {'settings is list': [], 'settings is string': 'x', 'settings is null': None,
               'interface None': v2_settings(interface=None),
               'client_network int': v2_settings(client_network=5),
               'client_network None': v2_settings(client_network=None),
               'hubs None': v2_settings(hubs=None),
               'hub table None': v2_settings(hubs={'hub_de': {'index': 1, 'interface': 'awg1',
                                                              'table': None}}),
               'hub table float': v2_settings(hubs={'hub_de': {'index': 1, 'interface': 'awg1',
                                                               'table': 10010.0}}),
               'stub None': v2_settings(stub_table=None),
               'stub list': v2_settings(stub_table=[10019])}
        for name, doc in bad.items():
            with self.subTest(case=name):
                self.calls.clear()
                (self.base / 'cascade-settings.json').write_bytes(json.dumps(doc).encode('utf-8'))
                self.write_bindings(HEADER)
                code, out, err = self.run_main()
                self.assertEqual(3, code, err)
                self.assertEqual('', out)
                self.assertEqual(1, len(err.strip().splitlines()), err)
                self.assertEqual([], self.calls)

    def test_binding_table_must_belong_to_a_hub(self):
        self.prepare(bindings='10.2.0.2 10019\n')
        with self.assertRaises(rules.RulesStateError):
            rules.sync(self.base)
        self.assertEqual([], self.calls)

    def test_settings_read_error_is_state_error(self):
        self.prepare()
        (self.base / 'cascade-settings.json').unlink()
        (self.base / 'cascade-settings.json').mkdir()
        with self.assertRaises(rules.RulesStateError):
            rules.sync(self.base)
        self.assertEqual([], self.calls)


class LockTest(RulesCase):
    def test_lock_taken_by_default_on_lock_file(self):
        self.prepare(show='')
        flock = MagicMock()
        with patch.object(rules.fcntl, 'flock', flock):
            rules.sync(self.base)
        self.assertTrue(flock.called)
        op = flock.call_args[0][1]
        self.assertTrue(op & rules.fcntl.LOCK_EX)
        self.assertTrue((self.base / '.cascade-rules.lock').exists())

    def test_no_lock_skips_flock(self):
        self.prepare(show='')
        flock = MagicMock()
        with patch.object(rules.fcntl, 'flock', flock):
            rules.sync(self.base, lock=False)
        flock.assert_not_called()

    def test_lock_timeout_raises_apply_error_without_ip(self):
        self.prepare()
        with patch.object(rules.fcntl, 'flock', side_effect=BlockingIOError()), \
                patch.object(rules, 'LOCK_TIMEOUT', 0.2):
            with self.assertRaises(rules.RulesApplyError):
                rules.sync(self.base)
        self.assertEqual([], self.calls)

    def test_lock_retried_until_it_succeeds(self):
        self.prepare(show='')
        attempts = []

        def flaky(fd, op):
            attempts.append(op)
            if len(attempts) < 3:
                raise BlockingIOError()
        with patch.object(rules.fcntl, 'flock', side_effect=flaky):
            rules.sync(self.base)
        self.assertEqual(3, len(attempts))

    def test_main_lock_timeout_gives_code_4(self):
        self.prepare()
        with patch.object(rules.fcntl, 'flock', side_effect=BlockingIOError()), \
                patch.object(rules, 'LOCK_TIMEOUT', 0.2):
            code, out, err = self.run_main()
        self.assertEqual((4, ''), (code, out))
        self.assertTrue(err.startswith('Error: '))
        self.assertEqual([], self.calls)

    def test_main_no_lock_works_even_if_lock_is_held(self):
        self.prepare(show='')
        with patch.object(rules.fcntl, 'flock', side_effect=BlockingIOError()), \
                patch.object(rules, 'LOCK_TIMEOUT', 0.2):
            code, out, err = self.run_main(['--config-dir', str(self.base), '--no-lock'])
        self.assertEqual(0, code, err)


class MainTest(RulesCase):
    def test_success_output_and_code(self):
        self.prepare()
        code, out, err = self.run_main()
        self.assertEqual((0, 'added=2 removed=2\n', ''), (code, out, err))

    def test_second_run_zero_changes(self):
        self.prepare(show=('10005:\tfrom 10.2.0.2 iif awg0 lookup 10010\n'
                           '10005:\tfrom 10.2.0.3 iif awg0 lookup 10020\n'
                           '10005:\tfrom 10.2.0.4 iif awg0 lookup 10010\n'))
        code, out, _ = self.run_main()
        self.assertEqual((0, 'added=0 removed=0\n'), (code, out))
        self.assertEqual(ROUTES + [SHOW_CMD], self.calls)

    def test_routes_are_not_counted(self):
        self.prepare(bindings='', show='')
        self.assertEqual('added=0 removed=0\n', self.run_main()[1])

    def test_state_error_gives_code_3_single_line_no_ip(self):
        self.write_settings()
        err = self.assertStateError(3)
        self.assertIn('Error:', err)
        self.assertEqual([], self.calls)

    def test_legacy_settings_code_3(self):
        self.write_settings({'interface': 'awg0', 'endpoint': 'x', 'dns': 'y'})
        self.write_bindings(HEADER)
        self.assertStateError(3)
        self.assertEqual([], self.calls)

    def test_permission_error_on_read_gives_code_3(self):
        self.prepare()
        real = Path.read_bytes

        def deny(path):
            if path.name == 'cascade-bindings.list':
                raise PermissionError('denied')
            return real(path)
        with patch.object(Path, 'read_bytes', deny):
            self.assertStateError(3)
        self.assertEqual([], self.calls)

    def test_ip_failure_gives_code_4(self):
        self.prepare()
        self.fail_on = lambda a: subprocess.CalledProcessError(2, ['ip', *a])
        self.assertStateError(4)

    def test_missing_ip_binary_gives_code_4(self):
        self.prepare()
        self.fail_on = lambda a: FileNotFoundError('ip')
        self.assertStateError(4)

    def test_unparsable_rule_gives_code_4_without_changes(self):
        self.prepare(show='10005:\tfrom 10.2.0.2 iif awg0 fwmark 0x1 lookup 10010\n')
        self.assertStateError(4)
        self.assertEqual(ROUTES + [SHOW_CMD], self.calls)

    def test_argument_error_exits_2(self):
        for argv in (['--bogus'], ['--config-dir'], ['extra-positional']):
            with self.subTest(argv=argv):
                with contextlib.redirect_stderr(io.StringIO()), \
                        contextlib.redirect_stdout(io.StringIO()) as out:
                    with self.assertRaises(SystemExit) as cm:
                        rules.main(argv)
                self.assertEqual(2, cm.exception.code)
                self.assertEqual('', out.getvalue())
        self.assertEqual([], self.calls)

    def test_config_dir_from_environment(self):
        self.prepare(show='')
        with patch.dict(os.environ, {'AWG_CONFIG_DIR': str(self.base)}):
            code, out, err = self.run_main([])
        self.assertEqual((0, 'added=3 removed=0\n'), (code, out), err)

    def test_config_dir_option_wins_over_environment(self):
        self.prepare(show='')
        with patch.dict(os.environ, {'AWG_CONFIG_DIR': str(self.base / 'nowhere')}):
            code, _, err = self.run_main()
        self.assertEqual(0, code, err)

    def test_no_lock_flag_accepted(self):
        self.prepare(show='')
        flock = MagicMock()
        with patch.object(rules.fcntl, 'flock', flock):
            code, out, err = self.run_main(['--config-dir', str(self.base), '--no-lock'])
        self.assertEqual(0, code, err)
        flock.assert_not_called()

    def test_default_run_takes_lock(self):
        self.prepare(show='')
        flock = MagicMock()
        with patch.object(rules.fcntl, 'flock', flock):
            self.run_main()
        self.assertTrue(flock.called)


if __name__ == '__main__':
    unittest.main()
