"""End-to-end consistency of file formats (contracts.md section 7.4)."""
import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import (KEY, LEGACY_HUBS, LEGACY_SETTINGS, TWO_HUBS, load_clients,  # noqa: E402
                     load_plugin, load_rules)

plugin = load_plugin()
rules = load_rules()
clients = load_clients()

CONFIG = ('[Interface]\nPrivateKey = server-private\nAddress = 10.2.0.1/24\nListenPort = 51820\n'
          'MTU = 1280\nJc = 4\nS1 = 30\n')
NKEY = 'N' * 43 + '='


def peer(name, key, octet):
    return f'\n[Peer]\n# {name}\nPublicKey = {key}\nAllowedIPs = 10.2.0.{octet}/32\n'


class RoundtripCase(unittest.TestCase):
    hubs = LEGACY_HUBS
    inventory = [{'name': 'phone', 'octet': 2}]
    add_hub = 'hub_de'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        topo = plugin.build_topology(copy.deepcopy(self.hubs), copy.deepcopy(LEGACY_SETTINGS))
        eff = plugin.effective_clients(copy.deepcopy(self.inventory), None, topo)
        self.settings = plugin.settings_document(topo, 'awg0', '203.0.113.10', '1.1.1.1')
        self.bindings = plugin.render_bindings(eff, topo)
        (self.base / 'cascade-settings.json').write_bytes(json.dumps(self.settings).encode('utf-8'))
        (self.base / 'cascade-bindings.list').write_bytes(self.bindings.encode('utf-8'))
        config = CONFIG
        for i, c in enumerate(eff['inventory']):
            config += peer(c['name'], chr(ord('P') + i) * 43 + '=', c['octet'])
        (self.base / 'awg0.conf').write_bytes(config.encode('utf-8'))
        self.calls = []
        for target, fake in (('awg', self.fake_awg), ('sync_rules', self.fake_sync)):
            p = patch.object(clients, target, side_effect=fake)
            p.start()
            self.addCleanup(p.stop)

    def fake_awg(self, *args, input=None):
        self.calls.append(('awg',) + tuple(args))
        return {'show': 'S' * 43 + '=', 'genkey': 'private-test-key', 'pubkey': NKEY}.get(args[0], '')

    def fake_sync(self, base):
        self.calls.append(('sync',))

    def bindings_on_disk(self):
        return (self.base / 'cascade-bindings.list').read_bytes().decode('utf-8')

    def run_manage(self, *args, **kwargs):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            clients.manage(self.base, *args, **kwargs)
        return out.getvalue()

    def test_rules_sync_accepts_plugin_output(self):
        ip_calls = []

        def fake_ip(*args):
            ip_calls.append(args)
            return ''
        with patch.object(rules, 'ip', side_effect=fake_ip):
            added, removed = rules.sync(self.base, lock=False)
        self.assertEqual(len(self.inventory), added)
        self.assertEqual(0, removed)
        tables = [c[-1] for c in ip_calls if c[1] == 'route']
        self.assertEqual(str(self.settings['stub_table']), tables[0])
        self.assertEqual(len(self.settings['hubs']) + 1, len(tables))

    def test_rules_main_exit_zero(self):
        with patch.object(rules, 'ip', return_value=''), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = rules.main(['--config-dir', str(self.base), '--no-lock'])
        self.assertEqual(0, code, err.getvalue())
        self.assertEqual(f'added={len(self.inventory)} removed=0\n', out.getvalue())

    def test_clients_list_accepts_plugin_output(self):
        listing = self.run_manage('list')
        rows = listing.splitlines()
        self.assertEqual('NAME\tADDRESS\tHUB\tPUBLIC KEY', rows[0])
        self.assertEqual(len(self.inventory) + 1, len(rows))
        for row, client in zip(rows[1:], self.inventory):
            cols = row.split('\t')
            self.assertEqual(client['name'], cols[0])
            self.assertNotIn(cols[2], ('?', '-'))

    def test_add_with_hub_then_remove_restores_bindings_bytes(self):
        out = self.run_manage('add', 'tablet', hub=self.add_hub)
        self.assertIn('tablet', out)
        after_add = self.bindings_on_disk()
        self.assertNotEqual(self.bindings, after_add)
        table = self.settings['hubs'][self.add_hub]['table']
        self.assertIn(f' {table}\n', after_add)
        self.assertEqual(('sync',), next(c for c in self.calls if c[0] == 'sync'))
        self.run_manage('remove', 'tablet')
        self.assertEqual(self.bindings, self.bindings_on_disk())
        self.assertEqual(self.bindings.encode('utf-8'),
                         (self.base / 'cascade-bindings.list').read_bytes())

    def test_sync_accepts_files_after_add(self):
        self.run_manage('add', 'tablet', hub=self.add_hub)
        with patch.object(rules, 'ip', return_value=''):
            added, _ = rules.sync(self.base, lock=False)
        self.assertEqual(len(self.inventory) + 1, added)

    def test_list_after_add_shows_chosen_hub(self):
        self.run_manage('add', 'tablet', hub=self.add_hub)
        rows = [r.split('\t') for r in self.run_manage('list').splitlines()[1:]]
        row = next(r for r in rows if r[0] == 'tablet')
        self.assertEqual(self.add_hub, row[2])


class OneHubRoundtripTest(RoundtripCase):
    pass


class TwoHubRoundtripTest(RoundtripCase):
    hubs = TWO_HUBS
    inventory = [{'name': 'phone', 'octet': 2}, {'name': 'me', 'octet': 3, 'hub': 'hub_us'}]
    add_hub = 'hub_us'

    def test_list_shows_both_hubs(self):
        rows = [r.split('\t') for r in self.run_manage('list').splitlines()[1:]]
        self.assertEqual(['hub_de', 'hub_us'], [r[2] for r in rows])


if __name__ == '__main__':
    unittest.main()
