"""Client manager (cascade_clients.py), contracts.md sections 2.3, 2.4 and 4."""
import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import load_clients  # noqa: E402

clients = load_clients()

HEADER = '# Managed by amneziawg-cascade. Format: <client address> <routing table>\n'
PKEY = 'P' * 43 + '='      # phone public key in config
NKEY = 'N' * 43 + '='      # public key produced by fake `awg pubkey`
SKEY = 'S' * 43 + '='      # server public key (awg show)
CONFIG = ('[Interface]\nPrivateKey = server-private\nAddress = 10.2.0.1/24\nListenPort = 51820\n'
          'MTU = 1280\nJc = 4\nS1 = 30\n\n[Peer]\n# phone\nPublicKey = ' + PKEY +
          '\nAllowedIPs = 10.2.0.2/32\n')
LEGACY = {'interface': 'awg0', 'endpoint': '203.0.113.10', 'dns': '1.1.1.1'}
V2 = {'interface': 'awg0', 'endpoint': '203.0.113.10', 'dns': '1.1.1.1',
      'client_network': '10.2.0.0/24', 'default_hub': 'hub_de', 'stub_table': 10019,
      'hubs': {'hub_de': {'index': 1, 'interface': 'awg1', 'table': 10010},
               'hub_us': {'index': 2, 'interface': 'awghub2', 'table': 10020}}}
JOURNAL = '.cascade-client-transaction.json'


def b64(text):
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


class Case(unittest.TestCase):
    settings = LEGACY
    bindings = None   # text of cascade-bindings.list or None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.config = self.base / 'awg0.conf'
        self.put('awg0.conf', CONFIG)
        self.put('cascade-settings.json', json.dumps(self.settings))
        if self.bindings is not None:
            self.put('cascade-bindings.list', self.bindings)
        self.calls = []
        self.snapshots = []
        self.awg_hook = None
        self.sync_hook = None
        self.show_result = SKEY
        for target, fake in (('awg', self.fake_awg), ('sync_rules', self.fake_sync)):
            p = patch.object(clients, target, side_effect=fake)
            p.start()
            self.addCleanup(p.stop)

    # --- fakes ---
    def snapshot(self, label):
        j = self.base / JOURNAL
        self.snapshots.append({
            'label': label,
            'config': self.read('awg0.conf'),
            'bindings': self.read('cascade-bindings.list'),
            'registry': self.read('cascade-clients.json'),
            'journal': json.loads(j.read_bytes().decode('utf-8')) if j.exists() else None})

    def fake_awg(self, *args, input=None):
        self.calls.append(tuple(args))
        if args[0] == 'pubkey':
            self.last_input = input
        if args[0] == 'set':
            self.snapshot('set')
        if self.awg_hook is not None:
            self.awg_hook(args)
        if args[0] == 'show':
            if isinstance(self.show_result, Exception):
                raise self.show_result
            return self.show_result
        if args[0] == 'genkey':
            return 'private-test-key'
        if args[0] == 'pubkey':
            return NKEY
        return ''

    def fake_sync(self, base):
        self.calls.append(('sync',))
        self.snapshot('sync')
        if self.sync_hook is not None:
            self.sync_hook()

    # --- file helpers ---
    def put(self, rel, text):
        (self.base / rel).write_bytes(text.encode('utf-8'))

    def read(self, rel):
        p = self.base / rel
        return p.read_bytes().decode('utf-8') if p.exists() else None

    def call(self, action, name=None, hub=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            clients.manage(self.base, action, name, hub)
        return out.getvalue()

    def call_err(self, action, name=None, hub=None):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            try:
                self.call(action, name, hub)
            except BaseException as exc:  # noqa: BLE001
                self.raised = exc
        return err.getvalue()

    def files_state(self):
        return {p.name: p.read_bytes() for p in self.base.rglob('*')
                if p.is_file() and p.suffix != '.lock'}

    def write_journal(self, doc):
        (self.base / JOURNAL).write_bytes(json.dumps(doc).encode('utf-8'))

    def registry(self):
        return json.loads(self.read('cascade-clients.json'))


class LegacyTest(Case):
    def test_add_and_list_do_not_expose_private_keys(self):
        result = self.call('add', 'tablet')
        profile = self.base / 'cascade-clients/tablet.conf'
        text = profile.read_bytes().decode('utf-8')
        self.assertIn(str(profile), result)
        self.assertIn('Endpoint = 203.0.113.10:51820', text)
        self.assertIn('Address = 10.2.0.3/32', text)
        self.assertIn('S1 = 30', text)
        listing = self.call('list')
        self.assertIn('tablet', listing)
        self.assertNotIn('private-test-key', listing + result)
        self.assertNotIn('server-private', listing + result)
        registry = self.registry()
        self.assertEqual('tablet', registry['clients'][0]['name'])
        self.assertNotIn('private', json.dumps(registry))

    @unittest.skipIf(os.name == 'nt', 'POSIX permissions')
    def test_profile_mode_is_0600(self):
        self.call('add', 'tablet')
        self.assertEqual(0o600, (self.base / 'cascade-clients/tablet.conf').stat().st_mode & 0o777)

    def test_remove_inventory_client_persists_revocation(self):
        self.call('remove', 'phone')
        self.assertNotIn('# phone', self.read('awg0.conf'))
        self.assertIn('phone', self.registry()['removed'])
        self.assertIn(('set', 'awg0', 'peer', PKEY, 'remove'), self.calls)

    def test_remove_dynamic_client_and_reuse_address(self):
        self.call('add', 'tablet')
        self.call('remove', 'tablet')
        self.assertFalse((self.base / 'cascade-clients/tablet.conf').exists())
        self.assertFalse((self.base / 'cascade-keys/client-tablet.key').exists())
        self.call('add', 'replacement')
        self.assertIn('10.2.0.3/32', self.read('cascade-clients/replacement.conf'))

    def test_failed_runtime_apply_restores_files(self):
        original = self.config.read_bytes()

        def fail(args):
            if args[0] == 'set':
                raise RuntimeError('apply failed')
        self.awg_hook = fail
        with self.assertRaises(RuntimeError):
            self.call('add', 'tablet')
        with self.assertRaises(RuntimeError):
            self.call('remove', 'phone')
        self.assertEqual(original, self.config.read_bytes())
        self.assertFalse((self.base / 'cascade-clients/tablet.conf').exists())
        self.assertFalse((self.base / 'cascade-clients.json').exists())
        self.assertFalse((self.base / JOURNAL).exists())

    def test_interrupted_remove_is_recovered_on_next_command(self):
        original = self.config.read_bytes()

        def interrupt(args):
            if args[0] == 'set':
                raise KeyboardInterrupt()
        self.awg_hook = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.call('remove', 'phone')
        self.assertTrue((self.base / JOURNAL).exists())
        self.awg_hook = None
        self.call('list')
        self.assertEqual(original, self.config.read_bytes())
        self.assertFalse((self.base / 'cascade-clients.json').exists())
        self.assertFalse((self.base / JOURNAL).exists())

    def test_deploy_marker_and_bad_names_block_mutation(self):
        original = self.config.read_bytes()
        for name in ['../bad', 'phone', 'a name', '', 'a' * 33]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.call('add', name)
        (self.base / '.cascade-deploy').mkdir()
        with self.assertRaises(ValueError):
            self.call('add', 'tablet')
        with self.assertRaises(ValueError):
            self.call('remove', 'phone')
        self.assertEqual(original, self.config.read_bytes())
        self.assertEqual([], self.calls)

    def test_list_format_with_hub_column(self):
        self.assertEqual('NAME\tADDRESS\tHUB\tPUBLIC KEY\nphone\t10.2.0.2/32\t-\t' + PKEY + '\n',
                         self.call('list'))

    def test_add_call_sequence_has_no_sync(self):
        self.call('add', 'tablet')
        self.assertEqual([('genkey',), ('pubkey',), ('show', 'awg0', 'public-key'),
                          ('set', 'awg0', 'peer', NKEY, 'allowed-ips', '10.2.0.3/32')], self.calls)
        self.assertEqual('private-test-key', self.last_input.strip() if self.last_input else None)

    def test_remove_call_sequence_has_no_sync(self):
        self.call('remove', 'phone')
        self.assertEqual([('set', 'awg0', 'peer', PKEY, 'remove')], self.calls)

    def test_bindings_never_created_or_changed(self):
        self.call('add', 'tablet')
        self.call('remove', 'tablet')
        self.assertIsNone(self.read('cascade-bindings.list'))

    def test_bindings_untouched_if_present(self):
        self.put('cascade-bindings.list', 'whatever\n')
        self.call('add', 'tablet')
        self.assertEqual('whatever\n', self.read('cascade-bindings.list'))

    def test_hub_option_is_error_and_touches_nothing(self):
        before = self.files_state()
        with self.assertRaises(ValueError):
            self.call('add', 'tablet', hub='hub_de')
        self.assertEqual(before, self.files_state())
        self.assertEqual([], self.calls)

    def test_registry_has_no_hub_field(self):
        self.call('add', 'tablet')
        self.assertEqual(['name', 'octet', 'public_key'], list(self.registry()['clients'][0]))

    def test_journal_is_v2_with_awg_undo_and_removed_on_success(self):
        seen = {}

        def look(args):
            if args[0] == 'set':
                seen['journal'] = self.snapshots[-1]['journal']
        self.awg_hook = look
        self.call('add', 'tablet')
        j = seen['journal']
        self.assertEqual(2, j['version'])
        self.assertEqual([['awg', 'set', 'awg0', 'peer', NKEY, 'remove']], j['undo'])
        self.assertFalse((self.base / JOURNAL).exists())

    def test_remove_journal_restores_allowed_ips(self):
        seen = {}

        def look(args):
            if args[0] == 'set':
                seen['j'] = self.snapshots[-1]['journal']
        self.awg_hook = look
        self.call('remove', 'phone')
        self.assertEqual([['awg', 'set', 'awg0', 'peer', PKEY, 'allowed-ips', '10.2.0.2/32']],
                         seen['j']['undo'])

    def test_legacy_v1_journal_is_recovered(self):
        original = CONFIG
        self.put('awg0.conf', CONFIG + '\n[Peer]\n# x\nPublicKey = ' + NKEY +
                 '\nAllowedIPs = 10.2.0.9/32\n')
        self.write_journal({'undo': ['set', 'awg0', 'peer', NKEY, 'remove'],
                            'previous': {'awg0.conf': b64(original), 'cascade-clients.json': None}})
        self.call('list')
        self.assertEqual(original, self.read('awg0.conf'))
        self.assertEqual([('show', 'awg0', 'public-key'),
                          ('set', 'awg0', 'peer', NKEY, 'remove')], self.calls)
        self.assertFalse((self.base / JOURNAL).exists())

    def test_invalid_interface_in_settings_is_error(self):
        self.put('cascade-settings.json', json.dumps({**LEGACY, 'interface': 'bad iface'}))
        with self.assertRaises(ValueError):
            self.call('list')


class V2Case(Case):
    settings = V2
    bindings = HEADER + '10.2.0.2 10010\n'


class V2AddTest(V2Case):
    def test_add_default_hub_full_call_sequence(self):
        self.call('add', 'tablet')
        self.assertEqual([('genkey',), ('pubkey',), ('show', 'awg0', 'public-key'), ('sync',),
                          ('set', 'awg0', 'peer', NKEY, 'allowed-ips', '10.2.0.3/32')], self.calls)
        self.assertEqual('private-test-key', self.last_input.strip())
        self.assertEqual(HEADER + '10.2.0.2 10010\n10.2.0.3 10010\n',
                         self.read('cascade-bindings.list'))

    def test_add_with_hub_us(self):
        out = self.call('add', 'tablet', hub='hub_us')
        self.assertIn(str(self.base / 'cascade-clients/tablet.conf'), out)
        self.assertEqual(HEADER + '10.2.0.2 10010\n10.2.0.3 10020\n',
                         self.read('cascade-bindings.list'))
        entry = self.registry()['clients'][0]
        self.assertEqual(['name', 'octet', 'public_key', 'hub'], list(entry))
        self.assertEqual({'name': 'tablet', 'octet': 3, 'public_key': NKEY, 'hub': 'hub_us'}, entry)

    def test_registry_hub_written_for_default_hub(self):
        self.call('add', 'tablet')
        self.assertEqual('hub_de', self.registry()['clients'][0]['hub'])

    def test_registry_serialization_format(self):
        self.call('add', 'tablet', hub='hub_us')
        expected = json.dumps({'clients': [{'name': 'tablet', 'octet': 3, 'public_key': NKEY,
                                            'hub': 'hub_us'}], 'removed': []}, indent=2) + '\n'
        self.assertEqual(expected, self.read('cascade-clients.json'))

    def test_default_hub_follows_settings(self):
        self.put('cascade-settings.json', json.dumps({**V2, 'default_hub': 'hub_us'}))
        self.call('add', 'tablet')
        self.assertIn('10.2.0.3 10020\n', self.read('cascade-bindings.list'))

    def test_files_state_at_sync_time(self):
        self.call('add', 'tablet', hub='hub_us')
        snap = next(s for s in self.snapshots if s['label'] == 'sync')
        self.assertIn('10.2.0.3 10020\n', snap['bindings'])
        self.assertIn('AllowedIPs = 10.2.0.3/32', snap['config'])
        self.assertIn(NKEY, snap['config'])

    def test_journal_v2_written_before_files_change(self):
        self.call('add', 'tablet', hub='hub_us')
        journal = self.snapshots[0]['journal']
        self.assertEqual(2, journal['version'])
        self.assertEqual([['awg', 'set', 'awg0', 'peer', NKEY, 'remove'], ['sync-rules']],
                         journal['undo'])
        previous = journal['previous']
        self.assertEqual(b64(CONFIG), previous['awg0.conf'])
        self.assertEqual(b64(self.bindings), previous['cascade-bindings.list'])
        self.assertIn('cascade-clients.json', previous)
        self.assertIsNone(previous['cascade-clients.json'])
        self.assertFalse((self.base / JOURNAL).exists())

    def test_bindings_written_in_canonical_sorted_form(self):
        self.put('cascade-bindings.list', '# old header\n10.2.0.9 10020\n\n10.2.0.2 10010\n')
        self.call('add', 'tablet')
        self.assertEqual(HEADER + '10.2.0.2 10010\n10.2.0.3 10010\n10.2.0.9 10020\n',
                         self.read('cascade-bindings.list'))

    def test_bindings_written_with_lf_and_utf8_bytes(self):
        self.call('add', 'tablet')
        raw = (self.base / 'cascade-bindings.list').read_bytes()
        self.assertNotIn(b'\r', raw)
        self.assertTrue(raw.endswith(b'\n'))

    @unittest.skipIf(os.name == 'nt', 'POSIX permissions')
    def test_bindings_mode_0600_after_add(self):
        self.call('add', 'tablet')
        self.assertEqual(0o600, (self.base / 'cascade-bindings.list').stat().st_mode & 0o777)

    def test_unknown_hub_fails_before_any_effect(self):
        before = self.files_state()
        with self.assertRaises(ValueError) as cm:
            self.call('add', 'tablet', hub='hub_fr')
        self.assertIn('hub_fr', str(cm.exception))
        self.assertEqual(before, self.files_state())
        self.assertEqual([], self.calls)

    def test_missing_bindings_fails_before_any_effect(self):
        (self.base / 'cascade-bindings.list').unlink()
        before = self.files_state()
        with self.assertRaises(ValueError):
            self.call('add', 'tablet')
        self.assertEqual(before, self.files_state())
        self.assertEqual([], self.calls)

    def test_corrupted_bindings_fail_before_any_effect(self):
        for bad in ('10.2.0.2 10030\n', '10.2.0.2 10010\r\n', '10.2.0.2 10010\n10.2.0.2 10010\n',
                    'garbage\n'):
            with self.subTest(text=bad):
                self.put('cascade-bindings.list', bad)
                before = self.files_state()
                with self.assertRaises(ValueError):
                    self.call('add', 'tablet')
                self.assertEqual(before, self.files_state())
                self.assertEqual([], self.calls)

    def test_non_utf8_bindings_fail(self):
        (self.base / 'cascade-bindings.list').write_bytes(b'\xff\xfe\x00')
        with self.assertRaises(ValueError):
            self.call('add', 'tablet')
        self.assertEqual([], self.calls)

    def test_invalid_v2_settings_are_rejected(self):
        bad = [{**V2, 'hubs': {}}, {**V2, 'default_hub': 'nope'}, {**V2, 'stub_table': 10010},
               {**V2, 'client_network': '10.2.0.0/16'}, {**V2, 'stub_table': True},
               {**V2, 'hubs': {'hub_de': {'index': 1, 'interface': 'awg1', 'table': True}}}]
        for doc in bad:
            with self.subTest(settings=doc):
                self.put('cascade-settings.json', json.dumps(doc))
                with self.assertRaises(ValueError):
                    self.call('add', 'tablet')
                self.assertEqual([], self.calls)

    def test_deploy_marker_blocks_add(self):
        (self.base / '.cascade-deploy').mkdir()
        with self.assertRaises(ValueError):
            self.call('add', 'tablet', hub='hub_us')
        self.assertEqual([], self.calls)

    def test_hub_with_remove_or_list_is_error(self):
        for action, name in (('remove', 'phone'), ('list', None)):
            with self.subTest(action=action):
                before = self.files_state()
                with self.assertRaises(ValueError) as cm:
                    self.call(action, name, hub='hub_us')
                self.assertIn('--hub', str(cm.exception))
                self.assertEqual(before, self.files_state())
                self.assertEqual([], self.calls)

    def test_bad_name_with_hub_still_value_error_without_effects(self):
        with self.assertRaises(ValueError):
            self.call('add', '../x', hub='hub_us')
        self.assertEqual([], self.calls)

    def test_existing_peer_name_is_rejected(self):
        with self.assertRaises(ValueError):
            self.call('add', 'phone')
        self.assertNotIn(('sync',), self.calls)

    def test_add_then_remove_returns_bindings_to_initial(self):
        self.call('add', 'tablet', hub='hub_us')
        self.call('remove', 'tablet')
        self.assertEqual(self.bindings, self.read('cascade-bindings.list'))


class V2RemoveTest(V2Case):
    def test_remove_call_sequence_and_state_at_sync(self):
        out = self.call('remove', 'phone')
        self.assertEqual('Removed: phone', out.strip())
        self.assertEqual([('set', 'awg0', 'peer', PKEY, 'remove'), ('sync',)], self.calls)
        snap = next(s for s in self.snapshots if s['label'] == 'sync')
        self.assertNotIn('10.2.0.2', snap['bindings'])
        self.assertEqual(HEADER, self.read('cascade-bindings.list'))
        self.assertIn('phone', self.registry()['removed'])

    def test_remove_journal_steps_order(self):
        self.call('remove', 'phone')
        journal = self.snapshots[0]['journal']
        self.assertEqual(2, journal['version'])
        self.assertEqual([['sync-rules'],
                          ['awg', 'set', 'awg0', 'peer', PKEY, 'allowed-ips', '10.2.0.2/32']],
                         journal['undo'])
        self.assertEqual(b64(self.bindings), journal['previous']['cascade-bindings.list'])
        self.assertEqual(b64(CONFIG), journal['previous']['awg0.conf'])

    def test_remove_drops_every_allowed_ip_of_peer(self):
        self.put('awg0.conf', CONFIG + '\n[Peer]\n# multi\nPublicKey = ' + NKEY +
                 '\nAllowedIPs = 10.2.0.4/32, 10.2.0.5/32\n')
        self.put('cascade-bindings.list',
                 HEADER + '10.2.0.2 10010\n10.2.0.4 10020\n10.2.0.5 10020\n10.2.0.6 10010\n')
        self.call('remove', 'multi')
        self.assertEqual(HEADER + '10.2.0.2 10010\n10.2.0.6 10010\n',
                         self.read('cascade-bindings.list'))

    def test_remove_missing_bindings_fails_without_effects(self):
        (self.base / 'cascade-bindings.list').unlink()
        before = self.files_state()
        with self.assertRaises(ValueError):
            self.call('remove', 'phone')
        self.assertEqual(before, self.files_state())
        self.assertEqual([], self.calls)

    def test_remove_dynamic_client_cleans_files(self):
        self.call('add', 'tablet', hub='hub_us')
        self.calls.clear()
        self.call('remove', 'tablet')
        self.assertFalse((self.base / 'cascade-clients/tablet.conf').exists())
        self.assertEqual([('set', 'awg0', 'peer', NKEY, 'remove'), ('sync',)], self.calls)
        self.assertEqual([], self.registry()['clients'])


class V2RollbackTest(V2Case):
    def test_add_apply_failure_rolls_back_files_and_runs_undo_steps(self):
        original = self.files_state()
        state = {'n': 0}

        def fail_first_set(args):
            if args[0] == 'set':
                state['n'] += 1
                if state['n'] == 1:
                    raise RuntimeError('apply failed')
        self.awg_hook = fail_first_set
        with self.assertRaises(RuntimeError):
            self.call('add', 'tablet', hub='hub_us')
        self.assertEqual(original, self.files_state())
        self.assertEqual([('set', 'awg0', 'peer', NKEY, 'allowed-ips', '10.2.0.3/32'),
                          ('set', 'awg0', 'peer', NKEY, 'remove'), ('sync',)], self.calls[4:])
        self.assertFalse((self.base / JOURNAL).exists())

    def test_add_sync_failure_rolls_back(self):
        original = self.files_state()
        state = {'n': 0}

        def fail_first():
            state['n'] += 1
            if state['n'] == 1:
                raise RuntimeError('sync failed')
        self.sync_hook = fail_first
        with self.assertRaises(RuntimeError):
            self.call('add', 'tablet')
        self.assertEqual(original, self.files_state())
        self.assertEqual([('set', 'awg0', 'peer', NKEY, 'remove'), ('sync',)], self.calls[4:])

    def test_remove_sync_failure_rolls_back_in_mirrored_order(self):
        original = self.files_state()
        state = {'n': 0}

        def fail_first():
            state['n'] += 1
            if state['n'] == 1:
                raise RuntimeError('sync failed')
        self.sync_hook = fail_first
        with self.assertRaises(RuntimeError):
            self.call('remove', 'phone')
        self.assertEqual(original, self.files_state())
        self.assertEqual([('set', 'awg0', 'peer', PKEY, 'remove'), ('sync',), ('sync',),
                          ('set', 'awg0', 'peer', PKEY, 'allowed-ips', '10.2.0.2/32')], self.calls)

    def test_failed_rollback_step_does_not_stop_others_and_warns(self):
        state = {'n': 0}

        def hook(args):
            if args[0] == 'set':
                state['n'] += 1
                if state['n'] == 1:
                    raise RuntimeError('apply failed')
                raise ValueError('undo failed')
        self.awg_hook = hook
        stderr = self.call_err('add', 'tablet')
        self.assertIsInstance(self.raised, RuntimeError)
        self.assertIn('Warning: rollback step awg failed: ValueError', stderr)
        self.assertEqual(('sync',), self.calls[-1])
        self.assertFalse((self.base / JOURNAL).exists())

    def test_failed_sync_rollback_step_warns_and_continues(self):
        state = {'n': 0}

        def fail_all():
            state['n'] += 1
            raise OSError('sync dead')
        self.sync_hook = fail_all
        stderr = self.call_err('remove', 'phone')
        self.assertIsInstance(self.raised, OSError)
        self.assertIn('Warning: rollback step sync-rules failed: OSError', stderr)
        self.assertEqual(('set', 'awg0', 'peer', PKEY, 'allowed-ips', '10.2.0.2/32'),
                         self.calls[-1])
        self.assertFalse((self.base / JOURNAL).exists())

    def test_restore_failure_keeps_journal_skips_undo_and_reraises_original(self):
        original_atomic = clients.atomic
        broken = {'on': False}

        def atomic(*args, **kwargs):
            if broken['on']:
                raise OSError('disk gone')
            return original_atomic(*args, **kwargs)

        def fail(args):
            if args[0] == 'set':
                broken['on'] = True
                raise RuntimeError('apply failed')
        self.awg_hook = fail
        with patch.object(clients, 'atomic', atomic):
            stderr = self.call_err('add', 'tablet', hub='hub_us')
        self.assertIsInstance(self.raised, RuntimeError)
        self.assertIn('Warning: rollback could not restore files: OSError; run list-clients.sh',
                      stderr)
        self.assertTrue((self.base / JOURNAL).exists())
        # no undo steps were executed: set (failed) is the last call, no sync afterwards
        self.assertEqual(('set', 'awg0', 'peer', NKEY, 'allowed-ips', '10.2.0.3/32'),
                         self.calls[-1])
        # next command restores files from the journal and clears it
        self.awg_hook = None
        self.calls.clear()
        self.call('list')
        self.assertEqual(CONFIG, self.read('awg0.conf'))
        self.assertEqual(self.bindings, self.read('cascade-bindings.list'))
        self.assertFalse((self.base / JOURNAL).exists())

    def test_keyboard_interrupt_leaves_journal_and_next_run_recovers(self):
        original = self.files_state()

        def interrupt(args):
            if args[0] == 'set':
                raise KeyboardInterrupt()
        self.awg_hook = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.call('remove', 'phone')
        self.assertTrue((self.base / JOURNAL).exists())
        self.awg_hook = None
        self.calls.clear()
        self.call('list')
        self.assertEqual(original, self.files_state())
        self.assertEqual([('sync',), ('show', 'awg0', 'public-key'),
                          ('set', 'awg0', 'peer', PKEY, 'allowed-ips', '10.2.0.2/32')], self.calls)


class V2ListTest(V2Case):
    def setUp(self):
        super().setUp()
        self.put('awg0.conf', CONFIG + '\n[Peer]\n# me\nPublicKey = ' + NKEY +
                 '\nAllowedIPs = 10.2.0.3/32\n')
        self.put('cascade-bindings.list', HEADER + '10.2.0.2 10010\n10.2.0.3 10020\n')

    def test_example_output(self):
        self.assertEqual('NAME\tADDRESS\tHUB\tPUBLIC KEY\n'
                         'phone\t10.2.0.2/32\thub_de\t' + PKEY + '\n'
                         'me\t10.2.0.3/32\thub_us\t' + NKEY + '\n', self.call('list'))

    def test_no_external_calls_for_list(self):
        self.call('list')
        self.assertEqual([], self.calls)

    def test_address_not_in_bindings_shows_dash(self):
        self.put('cascade-bindings.list', HEADER + '10.2.0.2 10010\n')
        lines = self.call('list').splitlines()
        self.assertEqual('me\t10.2.0.3/32\t-\t' + NKEY, lines[2])

    def test_multiple_allowed_ips_show_dash(self):
        self.put('awg0.conf', CONFIG + '\n[Peer]\n# multi\nPublicKey = ' + NKEY +
                 '\nAllowedIPs = 10.2.0.4/32, 10.2.0.5/32\n')
        self.put('cascade-bindings.list', HEADER + '10.2.0.4 10010\n')
        row = self.call('list').splitlines()[2].split('\t')
        self.assertEqual(['multi', '-', NKEY], [row[0], row[2], row[3]])

    def test_missing_bindings_show_question_mark(self):
        (self.base / 'cascade-bindings.list').unlink()
        lines = self.call('list').splitlines()
        self.assertEqual('phone\t10.2.0.2/32\t?\t' + PKEY, lines[1])
        self.assertEqual('me\t10.2.0.3/32\t?\t' + NKEY, lines[2])

    def test_corrupted_bindings_show_question_mark(self):
        self.put('cascade-bindings.list', 'oops\n')
        for line in self.call('list').splitlines()[1:]:
            self.assertEqual('?', line.split('\t')[2])

    def test_private_keys_never_listed(self):
        self.assertNotIn('server-private', self.call('list'))

    def test_list_with_no_peers_prints_header_only(self):
        self.put('awg0.conf', CONFIG.split('[Peer]')[0])
        self.assertEqual('NAME\tADDRESS\tHUB\tPUBLIC KEY\n', self.call('list'))

    def test_list_does_not_require_deploy_marker_absence(self):
        (self.base / '.cascade-deploy').mkdir()
        self.assertIn('phone', self.call('list'))

    def test_invalid_settings_make_list_fail(self):
        self.put('cascade-settings.json', json.dumps({**V2, 'hubs': {}}))
        with self.assertRaises(ValueError):
            self.call('list')


class RecoverTest(V2Case):
    def setUp(self):
        super().setUp()
        self.modified = CONFIG + '\n[Peer]\n# junk\nPublicKey = ' + NKEY + '\nAllowedIPs = 10.2.0.9/32\n'
        self.put('awg0.conf', self.modified)
        self.put('cascade-clients.json', '{"clients": [], "removed": ["phone"]}\n')

    def v2_remove_journal(self):
        return {'version': 2,
                'undo': [['sync-rules'],
                         ['awg', 'set', 'awg0', 'peer', PKEY, 'allowed-ips', '10.2.0.2/32']],
                'previous': {'awg0.conf': b64(CONFIG), 'cascade-clients.json': None}}

    def test_v2_journal_restores_files_and_runs_steps_in_order(self):
        self.write_journal(self.v2_remove_journal())
        self.call('list')
        self.assertEqual(CONFIG, self.read('awg0.conf'))
        self.assertIsNone(self.read('cascade-clients.json'))
        self.assertEqual([('sync',), ('show', 'awg0', 'public-key'),
                          ('set', 'awg0', 'peer', PKEY, 'allowed-ips', '10.2.0.2/32')], self.calls)
        self.assertFalse((self.base / JOURNAL).exists())

    def test_files_restored_before_steps(self):
        self.write_journal(self.v2_remove_journal())
        self.call('list')
        self.assertEqual(CONFIG, self.snapshots[0]['config'])

    def test_interface_down_skips_awg_step_with_warning(self):
        self.write_journal(self.v2_remove_journal())
        self.show_result = subprocess.CalledProcessError(1, ['awg', 'show'])
        stderr = self.call_err('list')
        self.assertEqual([('sync',), ('show', 'awg0', 'public-key')], self.calls)
        self.assertIn('Warning: interface awg0 is not running; skipped awg step', stderr)
        self.assertEqual(CONFIG, self.read('awg0.conf'))
        self.assertFalse((self.base / JOURNAL).exists())

    def test_interface_with_none_or_empty_key_is_not_running(self):
        for result in ('(none)', ''):
            with self.subTest(show=result):
                self.put('awg0.conf', self.modified)
                self.write_journal(self.v2_remove_journal())
                self.show_result = result
                self.calls.clear()
                self.call('list')
                self.assertNotIn('set', [c[0] for c in self.calls])
                self.assertFalse((self.base / JOURNAL).exists())

    def test_sync_failure_is_warning_and_does_not_stop_recovery(self):
        self.write_journal(self.v2_remove_journal())

        def boom():
            raise RuntimeError('sync broke')
        self.sync_hook = boom
        stderr = self.call_err('list')
        self.assertIsNone(getattr(self, 'raised', None))
        self.assertIn('Warning: recovery step sync-rules failed: RuntimeError', stderr)
        self.assertEqual(('set', 'awg0', 'peer', PKEY, 'allowed-ips', '10.2.0.2/32'),
                         self.calls[-1])
        self.assertFalse((self.base / JOURNAL).exists())

    def test_awg_set_failure_on_running_interface_propagates_and_keeps_journal(self):
        self.write_journal(self.v2_remove_journal())

        def fail(args):
            if args[0] == 'set':
                raise RuntimeError('set failed')
        self.awg_hook = fail
        with self.assertRaises(RuntimeError):
            self.call('list')
        self.assertTrue((self.base / JOURNAL).exists())

    def test_file_restore_failure_propagates_no_steps_journal_stays(self):
        self.write_journal(self.v2_remove_journal())
        with patch.object(clients, 'atomic', side_effect=OSError('nope')):
            with self.assertRaises(OSError):
                self.call('list')
        self.assertEqual([], self.calls)
        self.assertTrue((self.base / JOURNAL).exists())

    def test_v1_journal_restored_as_awg_step(self):
        self.write_journal({'undo': ['set', 'awg0', 'peer', NKEY, 'remove'],
                            'previous': {'awg0.conf': b64(CONFIG), 'cascade-clients.json': None}})
        self.call('list')
        self.assertEqual([('show', 'awg0', 'public-key'),
                          ('set', 'awg0', 'peer', NKEY, 'remove')], self.calls)
        self.assertEqual(CONFIG, self.read('awg0.conf'))
        self.assertFalse((self.base / JOURNAL).exists())

    def test_v1_journal_with_interface_down_is_skipped(self):
        self.write_journal({'undo': ['set', 'awg0', 'peer', NKEY, 'remove'],
                            'previous': {'awg0.conf': b64(CONFIG)}})
        self.show_result = subprocess.CalledProcessError(1, ['awg'])
        self.call('list')
        self.assertEqual([('show', 'awg0', 'public-key')], self.calls)
        self.assertFalse((self.base / JOURNAL).exists())

    def test_recovery_restores_bindings_file_too(self):
        self.put('cascade-bindings.list', HEADER)
        doc = self.v2_remove_journal()
        doc['previous']['cascade-bindings.list'] = b64(self.bindings)
        self.write_journal(doc)
        self.call('list')
        self.assertEqual(self.bindings, self.read('cascade-bindings.list'))

    def test_recover_is_noop_without_journal(self):
        clients.recover(self.base)
        self.assertEqual([], self.calls)
        self.assertEqual(self.modified, self.read('awg0.conf'))

    def test_recover_direct_call_v2(self):
        self.write_journal(self.v2_remove_journal())
        clients.recover(self.base)
        self.assertEqual(CONFIG, self.read('awg0.conf'))
        self.assertFalse((self.base / JOURNAL).exists())

    def test_recovery_runs_for_add_before_the_action(self):
        self.write_journal(self.v2_remove_journal())
        self.put('cascade-bindings.list', self.bindings)
        self.call('add', 'tablet')
        self.assertEqual(('sync',), self.calls[0])
        self.assertFalse((self.base / JOURNAL).exists())

    def test_unreadable_journals_raise_value_error_and_stay(self):
        good_prev = {'awg0.conf': b64(CONFIG)}
        bad = {
            'version 3': {'version': 3, 'undo': [], 'previous': good_prev},
            'unknown step ip': {'version': 2, 'undo': [['ip', 'rule']], 'previous': good_prev},
            'awg int': {'version': 2, 'undo': [['awg', 1]], 'previous': good_prev},
            'awg short': {'version': 2, 'undo': [['awg']], 'previous': good_prev},
            'awg non-string': {'version': 2, 'undo': [['awg', 'set', 'awg0', 5]],
                               'previous': good_prev},
            'sync with args': {'version': 2, 'undo': [['sync-rules', 'x']], 'previous': good_prev},
            'previous not object': {'version': 2, 'undo': [], 'previous': []},
            'v1 empty undo': {'undo': [], 'previous': good_prev},
            'v1 first not set': {'undo': ['peer', 'x', 'remove'], 'previous': good_prev},
            'v1 non-string': {'undo': ['set', 1], 'previous': good_prev},
            'undo not list': {'version': 2, 'undo': 'x', 'previous': good_prev},
        }
        for rel in ('', '/etc/passwd', 'a\\b', 'C:/x', '../x', 'a/../../x', '\\x'):
            bad['bad path %r' % rel] = {'version': 2, 'undo': [], 'previous': {rel: None}}
        for name, doc in bad.items():
            with self.subTest(case=name):
                self.write_journal(doc)
                before = self.files_state()
                with self.assertRaises(ValueError):
                    self.call('list')
                self.assertEqual(before, self.files_state())
                self.assertEqual([], self.calls)

    def test_invalid_json_journal(self):
        (self.base / JOURNAL).write_bytes(b'{not json')
        with self.assertRaises(ValueError):
            self.call('list')
        self.assertTrue((self.base / JOURNAL).exists())

    def test_non_utf8_journal(self):
        (self.base / JOURNAL).write_bytes(b'\xff\xfe{}')
        with self.assertRaises(ValueError):
            self.call('list')
        self.assertTrue((self.base / JOURNAL).exists())

    def test_invalid_settings_checked_before_recovery(self):
        self.put('cascade-settings.json', json.dumps({**V2, 'hubs': {}}))
        self.write_journal(self.v2_remove_journal())
        with self.assertRaises(ValueError):
            self.call('list')
        self.assertTrue((self.base / JOURNAL).exists())
        self.assertEqual([], self.calls)


if __name__ == '__main__':
    unittest.main()
