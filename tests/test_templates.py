"""Templates (contracts.md section 5): rendered with pure jinja2, byte-for-byte references."""
import copy
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import (ROOT, LEGACY_HUBS, LEGACY_SETTINGS, TWO_HUBS, VARS, golden,  # noqa: E402
                     load_plugin)

plugin = load_plugin()
TEMPLATES = ROOT / 'roles/amneziawg-cascade/templates'
MISSING = ('jinja2 is required: .venv\\Scripts\\python -m pip install -r requirements-dev.txt')

try:
    import jinja2
except ImportError:  # must FAIL, not skip
    jinja2 = None


class TemplateCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if jinja2 is None:
            raise AssertionError(MISSING)

    def render(self, name, **variables):
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)), trim_blocks=True,
                                 keep_trailing_newline=True, undefined=jinja2.StrictUndefined)
        src = (TEMPLATES / name).read_bytes().decode('utf-8')
        text = env.get_template(name).render(**variables)
        need = len(src) - len(src.rstrip('\n'))
        have = len(text) - len(text.rstrip('\n'))
        if need > have:
            text += '\n' * (need - have)
        return text.encode('utf-8')

    def variables(self, hubs, role, hostname, item, **over):
        topo = plugin.build_topology(copy.deepcopy(hubs), copy.deepcopy(LEGACY_SETTINGS))
        links = plugin.link_map(topo, role, hostname, 'awg2')
        data = copy.deepcopy(VARS)
        data.update(awg_topology=topo, awg_links=links, awg_node_role=role, item=item)
        data.update(over)
        return data

    def gate(self, hubs, template, item, **over):
        return self.render(template, **self.variables(hubs, 'gate', 'gate_ru', item, **over))

    def hub(self, hubs, hostname, template, item='awg2', **over):
        return self.render(template, **self.variables(hubs, 'hub', hostname, item, **over))


def sub(data, *pairs):
    text = data.decode('utf-8')
    for old, new in pairs:
        assert old in text, old
        text = text.replace(old, new)
    return text.encode('utf-8')


class LegacyGoldenTest(TemplateCase):
    def test_jinja2_available(self):
        self.assertIsNotNone(jinja2, MISSING)

    def test_golden_files_have_expected_endings(self):
        self.assertTrue(golden('server_gate_awg0.golden').endswith(b'/32\n\n'))
        self.assertTrue(golden('server_gate_awg1.golden').endswith(b'25\n'))
        self.assertNotIn(b'\r', golden('hook_gate_awg0_two.golden'))

    def test_gate_awg0_server(self):
        self.assertEqual(golden('server_gate_awg0.golden'),
                         self.gate(LEGACY_HUBS, 'server.conf.j2', 'awg0'))

    def test_gate_awg1_server(self):
        self.assertEqual(golden('server_gate_awg1.golden'),
                         self.gate(LEGACY_HUBS, 'server.conf.j2', 'awg1'))

    def test_hub_awg2_server(self):
        self.assertEqual(golden('server_hub_awg2.golden'),
                         self.hub(LEGACY_HUBS, 'hub_de', 'server.conf.j2'))

    def test_gate_awg1_hook(self):
        self.assertEqual(golden('hook_gate_awg1.golden'),
                         self.gate(LEGACY_HUBS, 'hooks.sh.j2', 'awg1'))

    def test_hub_awg2_hook(self):
        self.assertEqual(golden('hook_hub_awg2.golden'),
                         self.hub(LEGACY_HUBS, 'hub_de', 'hooks.sh.j2'))

    def test_client_profile_unchanged(self):
        data = copy.deepcopy(VARS)
        data['item'] = {'name': 'phone', 'octet': 2}
        self.assertEqual(golden('client_phone.golden'), self.render('client.conf.j2', **data))

    def test_removed_and_unknown_client_not_in_awg0_server(self):
        text = self.gate(LEGACY_HUBS, 'server.conf.j2', 'awg0').decode('utf-8')
        self.assertNotIn('oldphone', text)


class TwoHubGoldenTest(TemplateCase):
    def test_gate_awg0_and_awg1_unchanged_by_second_hub(self):
        self.assertEqual(golden('server_gate_awg0.golden'),
                         self.gate(TWO_HUBS, 'server.conf.j2', 'awg0'))
        self.assertEqual(golden('server_gate_awg1.golden'),
                         self.gate(TWO_HUBS, 'server.conf.j2', 'awg1'))

    def test_hook_awg1_and_hub_de_unchanged_by_second_hub(self):
        self.assertEqual(golden('hook_gate_awg1.golden'),
                         self.gate(TWO_HUBS, 'hooks.sh.j2', 'awg1'))
        self.assertEqual(golden('hook_hub_awg2.golden'),
                         self.hub(TWO_HUBS, 'hub_de', 'hooks.sh.j2'))
        self.assertEqual(golden('server_hub_awg2.golden'),
                         self.hub(TWO_HUBS, 'hub_de', 'server.conf.j2'))

    def test_gate_awghub2_server(self):
        expected = sub(golden('server_gate_awg1.golden'),
                       ('Address = 10.78.0.2/30', 'Address = 10.78.0.6/30'),
                       ('ListenPort = 51822', 'ListenPort = 51823'),
                       ('awg-cascade-awg1 up', 'awg-cascade-awghub2 up'),
                       ('awg-cascade-awg1 down', 'awg-cascade-awghub2 down'),
                       ('PublicKey = ' + 'D' * 43 + '=', 'PublicKey = ' + 'U' * 43 + '='),
                       ('Endpoint = 203.0.113.20:51821', 'Endpoint = 198.51.100.30:51821'))
        self.assertEqual(expected, self.gate(TWO_HUBS, 'server.conf.j2', 'awghub2'))

    def test_hub_us_server(self):
        expected = sub(golden('server_hub_awg2.golden'),
                       ('Address = 10.78.0.1/30', 'Address = 10.78.0.5/30'),
                       ('AllowedIPs = 10.78.0.2/32', 'AllowedIPs = 10.78.0.6/32'))
        self.assertEqual(expected, self.hub(TWO_HUBS, 'hub_us', 'server.conf.j2'))

    def test_gate_awghub2_hook(self):
        expected = sub(golden('hook_gate_awg1.golden'), ('awg1', 'awghub2'), ('10010', '10020'),
                       ('51822', '51823'))
        self.assertEqual(expected, self.gate(TWO_HUBS, 'hooks.sh.j2', 'awghub2'))

    def test_hub_us_hook(self):
        expected = sub(golden('hook_hub_awg2.golden'), ('10.78.0.2/32', '10.78.0.6/32'))
        self.assertEqual(expected, self.hub(TWO_HUBS, 'hub_us', 'hooks.sh.j2'))

    def test_gate_awg0_hook_two_hubs_reference(self):
        self.assertEqual(golden('hook_gate_awg0_two.golden'),
                         self.gate(TWO_HUBS, 'hooks.sh.j2', 'awg0'))

    def test_gate_awg0_hook_one_hub_drops_second_hub_lines(self):
        lines = golden('hook_gate_awg0_two.golden').decode('utf-8').splitlines(keepends=True)
        expected = ''.join(l for l in lines if 'awghub2' not in l and 'table 10020' not in l)
        self.assertEqual(expected.encode('utf-8'), self.gate(LEGACY_HUBS, 'hooks.sh.j2', 'awg0'))

    def test_gate_awg0_hook_without_ru_split(self):
        lines = golden('hook_gate_awg0_two.golden').decode('utf-8').split('\n')
        drop = set()
        for i, l in enumerate(lines):
            if '-o eth0 -s 10.2.0.0/24 -m mark --mark 0x64' in l or '-i eth0 -o awg0 -d 10.2.0.0/24' in l:
                drop.add(i)
        starts = [i for i, l in enumerate(lines) if l == '    flush_rules 10000']
        self.assertEqual(2, len(starts))
        drop.update(range(starts[0], starts[0] + 5))
        drop.update(range(starts[1], starts[1] + 4))
        expected = '\n'.join(l for i, l in enumerate(lines) if i not in drop)
        self.assertEqual(expected.encode('utf-8'),
                         self.gate(TWO_HUBS, 'hooks.sh.j2', 'awg0', awg_ru_split=False))


class Awg0HookInvariantTest(TemplateCase):
    def setUp(self):
        self.text = self.gate(TWO_HUBS, 'hooks.sh.j2', 'awg0').decode('utf-8')
        head, _, tail = self.text.partition('\nelse\n')
        self.up_part = head
        self.down = tail
        self.up = head.split('\n')

    def idx(self, line, lines=None):
        lines = self.up if lines is None else lines
        self.assertIn(line, lines)
        return lines.index(line)

    def test_up_order_lock_flush_stub_rule_flush_sync_unlock(self):
        order = [self.idx('    lock_rules'), self.idx('    flush_rules 10010'),
                 self.idx('    ip rule add from 10.2.0.0/24 iif awg0 priority 10010 lookup 10019'),
                 self.idx('    flush_rules 10005'),
                 self.idx('    /usr/local/sbin/awg-cascade-rules --no-lock'),
                 self.idx('    exec 9>&-')]
        self.assertEqual(sorted(order), order)

    def test_sync_line_is_exact_without_swallowing_errors(self):
        sync_lines = [l for l in self.text.split('\n') if 'awg-cascade-rules' in l and 'sbin' in l]
        self.assertEqual(['    /usr/local/sbin/awg-cascade-rules --no-lock'], sync_lines)

    def test_up_lock_without_or_true_down_with_or_true(self):
        self.assertIn('    lock_rules', self.up)
        self.assertNotIn('    lock_rules || true', self.up)
        self.assertIn('    lock_rules || true', self.down.split('\n'))

    def test_lock_function_uses_shared_path_and_timeout(self):
        m = re.search(r'^lock_rules\(\).*$', self.text, re.M)
        self.assertIsNotNone(m)
        self.assertIn('/etc/amnezia/amneziawg/.cascade-rules.lock', m.group(0))
        self.assertIn('flock -w 30', m.group(0))

    def test_unreachable_in_stub_and_every_hub_table(self):
        for table in (10019, 10010, 10020):
            self.assertIn(f'    ip route replace unreachable default metric 32760 table {table}',
                          self.up)

    def test_subnet_rule_points_to_stub_not_hub_table(self):
        rules = [l for l in self.up if 'priority 10010' in l and 'rule add' in l]
        self.assertEqual(1, len(rules))
        self.assertTrue(rules[0].endswith('lookup 10019'))

    def test_down_does_not_use_bindings_or_sync(self):
        self.assertNotIn('cascade-bindings.list', self.down)
        self.assertNotIn('awg-cascade-rules', self.down)

    def test_one_accept_pair_per_link_and_drop_for_link_network(self):
        for link in ('awg1', 'awghub2'):
            fwd = [l for l in self.up if f'-i awg0 -o {link} ' in l and l.endswith('-j ACCEPT')]
            back = [l for l in self.up if f'-i {link} -o awg0 ' in l]
            self.assertEqual(1, len(fwd), link)
            self.assertEqual(1, len(back), link)
        self.assertIn('    ipt -A "$chain" -i awg0 -d 10.78.0.0/24 -j DROP', self.up)

    def test_one_hub_has_no_second_link_artifacts(self):
        text = self.gate(LEGACY_HUBS, 'hooks.sh.j2', 'awg0').decode('utf-8')
        self.assertNotIn('awghub2', text)
        self.assertNotIn('10020', text)
        self.assertIn('lookup 10019', text)

    def test_input_rule_is_check_then_insert(self):
        self.assertIn('    ipt -C INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null || '
                      'ipt -I INPUT -p udp --dport 51820 -j ACCEPT', self.up)

    def test_no_ansible_filters_in_rendered_output(self):
        self.assertNotIn('{{', self.text)
        self.assertNotIn('{%', self.text)


class BashSyntaxTest(TemplateCase):
    BASH = Path('C:/Program Files/Git/bin/bash.exe')

    @unittest.skipUnless(BASH.exists() or os.name != 'nt', 'bash not available')
    def test_rendered_hooks_pass_bash_n(self):
        exe = str(self.BASH) if os.name == 'nt' else 'bash'
        cases = [self.gate(TWO_HUBS, 'hooks.sh.j2', 'awg0'),
                 self.gate(TWO_HUBS, 'hooks.sh.j2', 'awghub2'),
                 self.hub(TWO_HUBS, 'hub_us', 'hooks.sh.j2')]
        for data in cases:
            result = subprocess.run([exe, '-n'], input=data, capture_output=True)
            self.assertEqual(0, result.returncode, result.stderr.decode('utf-8', 'replace'))

    @unittest.skipUnless(BASH.exists() or os.name != 'nt', 'bash not available')
    def test_all_awg0_hook_variants_pass_bash_n(self):
        exe = str(self.BASH) if os.name == 'nt' else 'bash'
        variants = {'two hubs': self.gate(TWO_HUBS, 'hooks.sh.j2', 'awg0'),
                    'one hub': self.gate(LEGACY_HUBS, 'hooks.sh.j2', 'awg0'),
                    'no ru split': self.gate(TWO_HUBS, 'hooks.sh.j2', 'awg0', awg_ru_split=False),
                    'one hub no ru split': self.gate(LEGACY_HUBS, 'hooks.sh.j2', 'awg0',
                                                     awg_ru_split=False)}
        for name, data in variants.items():
            with self.subTest(variant=name):
                result = subprocess.run([exe, '-n'], input=data, capture_output=True)
                self.assertEqual(0, result.returncode, result.stderr.decode('utf-8', 'replace'))


class StrictVariablesTest(TemplateCase):
    def test_missing_variable_is_an_error(self):
        data = self.variables(LEGACY_HUBS, 'gate', 'gate_ru', 'awg1')
        del data['awg_links']
        with self.assertRaises(jinja2.UndefinedError):
            self.render('server.conf.j2', **data)

    def test_templates_do_not_need_removed_variables(self):
        # contracts 5.2: awg_hub, awg_hub_link_public_key, awg_link_subnet, ... are never read
        for forbidden in ('awg_hub_link_public_key', 'awg_link_subnet', 'awg_gate_link_port',
                          'awg_hub_port', 'awg_route_table', 'awg_gate_link_interface'):
            self.assertNotIn(forbidden, VARS)
        self.gate(LEGACY_HUBS, 'server.conf.j2', 'awg1')
        self.gate(LEGACY_HUBS, 'hooks.sh.j2', 'awg0')
        self.hub(LEGACY_HUBS, 'hub_de', 'server.conf.j2')
        self.hub(LEGACY_HUBS, 'hub_de', 'hooks.sh.j2')


if __name__ == '__main__':
    unittest.main()
