"""Filter plugin awg_cascade.py, contracts.md section 1."""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import (KEY, LEGACY_HUBS, LEGACY_SETTINGS, TWO_HUBS, HUB_DE, HUB_US,  # noqa: E402
                     load_plugin)

plugin = load_plugin()

DEFAULTS = {'link_interface': 'awg1', 'link_port': 51822, 'link_subnet': '10.78.0',
            'route_table': 10010}


class PluginCase(unittest.TestCase):
    def assertCode(self, code, func, *args, **kwargs):
        with self.assertRaises(plugin.CascadeInventoryError) as cm:
            func(*args, **kwargs)
        self.assertEqual(code, cm.exception.code)
        return cm.exception

    def topo(self, hubs=None, **overrides):
        settings = copy.deepcopy(LEGACY_SETTINGS)
        settings.update(overrides)
        return plugin.build_topology(copy.deepcopy(hubs if hubs is not None else TWO_HUBS), settings)

    def topo_code(self, code, hubs=None, **overrides):
        settings = copy.deepcopy(LEGACY_SETTINGS)
        settings.update(overrides)
        return self.assertCode(code, plugin.build_topology,
                               copy.deepcopy(hubs if hubs is not None else TWO_HUBS), settings)

    def two_hubs_with(self, **us_overrides):
        hubs = copy.deepcopy(TWO_HUBS)
        hubs[0].update(us_overrides)
        return hubs


class ErrorClassTest(PluginCase):
    def test_error_is_value_error_with_code_and_message(self):
        exc = plugin.CascadeInventoryError('gate_count', 'msg here')
        self.assertIsInstance(exc, ValueError)
        self.assertEqual('gate_count', exc.code)
        self.assertEqual('msg here', str(exc))


class HubParamsTest(PluginCase):
    def test_index_1_defaults(self):
        self.assertEqual({'index': 1, 'interface': 'awg1', 'gate_port': 51822,
                          'network': '10.78.0.0/30', 'hub_address': '10.78.0.1',
                          'gate_address': '10.78.0.2', 'table': 10010},
                         plugin.hub_params(1, DEFAULTS))

    def test_table_of_documented_indexes(self):
        expected = {
            2: ('awghub2', 51823, '10.78.0.4/30', '10.78.0.5', '10.78.0.6', 10020),
            3: ('awghub3', 51824, '10.78.0.8/30', '10.78.0.9', '10.78.0.10', 10030),
            64: ('awghub64', 51885, '10.78.0.252/30', '10.78.0.253', '10.78.0.254', 10640),
        }
        for n, (iface, port, net, hub, gate, table) in expected.items():
            with self.subTest(index=n):
                self.assertEqual({'index': n, 'interface': iface, 'gate_port': port,
                                  'network': net, 'hub_address': hub, 'gate_address': gate,
                                  'table': table}, plugin.hub_params(n, DEFAULTS))

    def test_index_1_with_overridden_variables(self):
        settings = {'link_interface': 'wgde', 'link_port': 40000, 'link_subnet': '10.99.5',
                    'route_table': 20000}
        self.assertEqual({'index': 1, 'interface': 'wgde', 'gate_port': 40000,
                          'network': '10.99.5.0/30', 'hub_address': '10.99.5.1',
                          'gate_address': '10.99.5.2', 'table': 20000},
                         plugin.hub_params(1, settings))

    def test_string_index_equals_int_index(self):
        self.assertEqual(plugin.hub_params(2, DEFAULTS), plugin.hub_params('2', DEFAULTS))

    def test_result_numbers_are_int(self):
        result = plugin.hub_params('2', {**DEFAULTS, 'link_port': '51822', 'route_table': '10010'})
        for key in ('index', 'gate_port', 'table'):
            self.assertIs(int, type(result[key]), key)

    def test_all_indexes_follow_formulas(self):
        for n in range(1, 65):
            r = plugin.hub_params(n, DEFAULTS)
            self.assertEqual(51822 + n - 1, r['gate_port'])
            self.assertEqual(10010 + 10 * (n - 1), r['table'])
            self.assertEqual(f'10.78.0.{4 * (n - 1)}/30', r['network'])
            self.assertEqual(f'10.78.0.{4 * (n - 1) + 1}', r['hub_address'])
            self.assertEqual(f'10.78.0.{4 * (n - 1) + 2}', r['gate_address'])

    def test_invalid_index_raises(self):
        for bad in (0, 65, -1, '02', True, 1.5, 'x', '', None, '0', '65'):
            with self.subTest(index=bad):
                self.assertCode('invalid_index', plugin.hub_params, bad, DEFAULTS)

    def test_does_not_mutate_settings(self):
        settings = dict(DEFAULTS)
        plugin.hub_params(3, settings)
        self.assertEqual(DEFAULTS, settings)


class StubTableTest(PluginCase):
    def test_stub_table_default(self):
        self.assertEqual(10019, plugin.stub_table({'route_table': 10010}))

    def test_stub_table_string_and_custom(self):
        self.assertEqual(20009, plugin.stub_table({'route_table': '20000'}))


class BuildTopologyTest(PluginCase):
    def test_legacy_single_hub_without_index(self):
        result = plugin.build_topology(copy.deepcopy(LEGACY_HUBS), copy.deepcopy(LEGACY_SETTINGS))
        self.assertEqual({'hubs': [HUB_DE], 'default_hub': 'hub_de', 'stub_table': 10019,
                          'client_network': '10.2.0.0/24', 'link_network': '10.78.0.0/24',
                          'gate_interfaces': ['awg1', 'awg0']}, result)

    def test_single_hub_with_empty_string_index(self):
        hubs = copy.deepcopy(LEGACY_HUBS)
        hubs[0]['index'] = ''
        self.assertEqual(HUB_DE, self.topo(hubs)['hubs'][0])

    def test_two_hubs_sorted_by_index(self):
        result = self.topo()
        self.assertEqual({'hubs': [HUB_DE, HUB_US], 'default_hub': 'hub_de', 'stub_table': 10019,
                          'client_network': '10.2.0.0/24', 'link_network': '10.78.0.0/24',
                          'gate_interfaces': ['awg1', 'awghub2', 'awg0']}, result)

    def test_single_hub_with_explicit_index_uses_it(self):
        hubs = copy.deepcopy(LEGACY_HUBS)
        hubs[0]['index'] = 2
        result = self.topo(hubs, default_hub='hub_de')
        self.assertEqual(2, result['hubs'][0]['index'])
        self.assertEqual('awghub2', result['hubs'][0]['interface'])
        self.assertEqual(['awghub2', 'awg0'], result['gate_interfaces'])

    def test_explicit_default_hub(self):
        self.assertEqual('hub_us', self.topo(default_hub='hub_us')['default_hub'])

    def test_empty_string_default_hub_means_not_set(self):
        self.assertEqual('hub_de', self.topo(default_hub='')['default_hub'])

    def test_string_numbers_give_same_result_as_int(self):
        hubs = copy.deepcopy(TWO_HUBS)
        hubs[0].update(index='2', hub_port='51821')
        hubs[1].update(hub_port='51821')
        result = self.topo(hubs, client_port='51820', link_port='51822', route_table='10010',
                           ru_table='10011')
        self.assertEqual(self.topo(), result)
        self.assertIs(int, type(result['hubs'][1]['hub_port']))
        self.assertIs(int, type(result['stub_table']))

    def test_public_keys_are_not_validated(self):
        hubs = copy.deepcopy(LEGACY_HUBS)
        hubs[0]['public_key'] = ''
        self.assertEqual('', self.topo(hubs)['hubs'][0]['public_key'])

    def test_arguments_not_mutated(self):
        hubs, settings = copy.deepcopy(TWO_HUBS), copy.deepcopy(LEGACY_SETTINGS)
        plugin.build_topology(hubs, settings)
        self.assertEqual(TWO_HUBS, hubs)
        self.assertEqual(LEGACY_SETTINGS, settings)

    def test_custom_link_variables_for_index_1(self):
        result = self.topo(LEGACY_HUBS, link_interface='wgde', link_port=40000,
                           link_subnet='10.99.5', route_table=20000, ru_table=20001)
        hub = result['hubs'][0]
        self.assertEqual(('wgde', 40000, '10.99.5.0/30', 20000), (
            hub['interface'], hub['gate_port'], hub['network'], hub['table']))
        self.assertEqual(20009, result['stub_table'])
        self.assertEqual('10.99.5.0/24', result['link_network'])
        self.assertEqual(['wgde', 'awg0'], result['gate_interfaces'])

    def test_max_index_64_is_accepted(self):
        hubs = copy.deepcopy(LEGACY_HUBS)
        hubs[0]['index'] = 64
        self.assertEqual('awghub64', self.topo(hubs, default_hub='hub_de')['hubs'][0]['interface'])

    # --- error codes ---
    def test_error_index_required(self):
        self.topo_code('index_required', self.two_hubs_with(index=None))
        self.topo_code('index_required', self.two_hubs_with(index=''))

    def test_error_duplicate_index(self):
        self.topo_code('duplicate_index', self.two_hubs_with(index=1))

    def test_error_invalid_index(self):
        for bad in (65, 0, '02', True, 1.5, 'x'):
            with self.subTest(index=bad):
                self.topo_code('invalid_index', self.two_hubs_with(index=bad))

    def test_error_table_collision(self):
        for table in (10020, 10019, 10010):
            with self.subTest(ru_table=table):
                self.topo_code('table_collision', ru_table=table)

    def test_error_port_collision(self):
        self.topo_code('port_collision', client_port=51823)
        self.topo_code('port_collision', LEGACY_HUBS, link_port=51820)

    def test_error_invalid_port(self):
        self.topo_code('invalid_port', link_port=65535)
        self.topo_code('invalid_port', client_port=0)
        self.topo_code('invalid_port', client_port=70000)
        self.topo_code('invalid_port', client_port='abc')
        self.topo_code('invalid_port', client_port=True)
        self.topo_code('invalid_port', hubs=self.two_hubs_with(hub_port=0))
        self.topo_code('invalid_port', hubs=self.two_hubs_with(hub_port=65536))

    def test_error_interface_collision(self):
        self.topo_code('interface_collision', link_interface='awghub2')
        self.topo_code('interface_collision', link_interface='awg0')

    def test_error_invalid_interface(self):
        self.topo_code('invalid_interface', link_interface='bad name')
        self.topo_code('invalid_interface', client_interface='1abc')
        self.topo_code('invalid_interface', hub_interface='a' * 16)
        self.topo_code('invalid_interface', hub_interface='')

    def test_error_network_overlap(self):
        self.topo_code('network_overlap', client_subnet='10.78.0')

    def test_error_invalid_subnet(self):
        self.topo_code('invalid_subnet', client_subnet='10.2.300')
        self.topo_code('invalid_subnet', link_subnet='192.168.0')
        self.topo_code('invalid_subnet', link_subnet='10.78.0.0')
        self.topo_code('invalid_subnet', client_subnet='10.2')

    def test_error_default_hub_unknown(self):
        self.topo_code('unknown_default_hub', default_hub='hub_fr')

    def test_error_default_hub_required(self):
        hubs = self.two_hubs_with(index=3)
        hubs[1]['index'] = 2
        self.topo_code('default_hub_required', hubs)

    def test_error_shared_host(self):
        self.topo_code('shared_host', self.two_hubs_with(host='203.0.113.10'))
        self.topo_code('shared_host', self.two_hubs_with(host='203.0.113.20'))

    def test_error_hub_is_gate(self):
        self.topo_code('hub_is_gate', self.two_hubs_with(name='gate_ru'))

    def test_error_gate_count(self):
        self.topo_code('gate_count', gates=[])
        self.topo_code('gate_count', gates=[{'name': 'g1', 'host': '203.0.113.10'},
                                            {'name': 'g2', 'host': '203.0.113.11'}])

    def test_error_hub_count(self):
        self.assertCode('hub_count', plugin.build_topology, [], copy.deepcopy(LEGACY_SETTINGS))

    def test_error_duplicate_hub(self):
        self.topo_code('duplicate_hub', self.two_hubs_with(name='hub_de'))

    def test_error_invalid_host(self):
        self.topo_code('invalid_host', self.two_hubs_with(host='-bad'))
        self.topo_code('invalid_host', self.two_hubs_with(host=5))
        self.topo_code('invalid_host', gates=[{'name': 'gate_ru', 'host': 'bad host'}])

    def test_error_invalid_table(self):
        self.topo_code('invalid_table', route_table=4294967290, hubs=LEGACY_HUBS)
        hubs = copy.deepcopy(LEGACY_HUBS)
        hubs[0]['index'] = 64
        self.topo_code('invalid_table', hubs, route_table=4294967000, default_hub='hub_de')
        self.topo_code('invalid_table', route_table=9999)
        self.topo_code('invalid_table', ru_table='x')
        self.topo_code('invalid_table', ru_table=4294967296)

    # --- section 7.1 / 7.2 ---
    def test_noncanonical_subnet_octets_are_invalid_subnet(self):
        for bad in ('10.02.0', '10.2.00', '010.2.0', '10..0', '.2.0', '10.2.', '10.2.0 ',
                    '10.2.x', '10.+2.0', '10.2.-1', ''):
            with self.subTest(client_subnet=bad):
                self.topo_code('invalid_subnet', client_subnet=bad)
        for bad in ('10.78.00', '10.078.0', '010.78.0', '10.78.', '10..0'):
            with self.subTest(link_subnet=bad):
                self.topo_code('invalid_subnet', link_subnet=bad)

    def test_canonical_subnets_accepted(self):
        self.assertEqual('10.2.0.0/24', self.topo(client_subnet='10.2.0')['client_network'])
        self.assertEqual('10.0.0.0/24', self.topo(client_subnet='10.0.0')['client_network'])
        self.assertEqual('10.2.255.0/24', self.topo(client_subnet='10.2.255')['client_network'])

    def test_public_key_is_str_in_outputs(self):
        for hub in self.topo()['hubs']:
            self.assertIs(str, type(hub['public_key']))

    def test_default_hub_none_like_values_mean_not_set(self):
        for value in (None, '', 'None'):
            with self.subTest(default_hub=value):
                result = self.topo(LEGACY_HUBS, default_hub=value)
                self.assertEqual('hub_de', result['default_hub'])
                result = self.topo(default_hub=value)
                self.assertEqual('hub_de', result['default_hub'])

    def test_default_hub_none_string_without_index_1_requires_default(self):
        hubs = self.two_hubs_with(index=3)
        hubs[1]['index'] = 2
        self.topo_code('default_hub_required', hubs, default_hub='None')


class LinkMapTest(PluginCase):
    def test_gate_role_maps_every_hub(self):
        result = plugin.link_map(self.topo(), 'gate', 'gate_ru', 'awg2')
        self.assertEqual({'awg1': HUB_DE, 'awghub2': HUB_US}, result)

    def test_hub_role_maps_hub_interface_to_own_hub(self):
        self.assertEqual({'awg2': HUB_US}, plugin.link_map(self.topo(), 'hub', 'hub_us', 'awg2'))
        self.assertEqual({'awg2': HUB_DE}, plugin.link_map(self.topo(), 'hub', 'hub_de', 'awg2'))

    def test_hub_role_unknown_host(self):
        self.assertCode('unknown_host', plugin.link_map, self.topo(), 'hub', 'hub_fr', 'awg2')

    def test_other_role_is_value_error(self):
        with self.assertRaises(ValueError):
            plugin.link_map(self.topo(), 'spoke', 'hub_de', 'awg2')


class CheckLinkKeysTest(PluginCase):
    def test_legacy_ok(self):
        self.assertIs(True, plugin.check_link_keys(self.topo(LEGACY_HUBS), KEY('G')))

    def test_two_hubs_ok(self):
        self.assertIs(True, plugin.check_link_keys(self.topo(), KEY('G')))

    def test_inherited_global_key_is_duplicate(self):
        hubs = copy.deepcopy(TWO_HUBS)
        for h in hubs:
            h['public_key'] = KEY('D')
        self.assertCode('duplicate_key', plugin.check_link_keys, self.topo(hubs), KEY('G'))

    def test_empty_hub_key_is_invalid(self):
        self.assertCode('invalid_key', plugin.check_link_keys,
                        self.topo(self.two_hubs_with(public_key='')), KEY('G'))

    def test_hub_key_equal_to_gate_key_is_duplicate(self):
        self.assertCode('duplicate_key', plugin.check_link_keys,
                        self.topo(self.two_hubs_with(public_key=KEY('G'))), KEY('G'))

    def test_invalid_gate_key(self):
        for bad in ('', 'short', KEY('G')[:-1] + '!'):
            with self.subTest(key=bad):
                self.assertCode('invalid_key', plugin.check_link_keys, self.topo(), bad)


class CheckClientsTest(PluginCase):
    def setUp(self):
        self.t = self.topo()

    def test_example(self):
        result = plugin.check_clients([{'name': 'phone', 'octet': 2},
                                       {'name': 'me', 'octet': '3', 'hub': 'hub_us'}], self.t)
        self.assertEqual([{'name': 'phone', 'octet': 2, 'hub': 'hub_de'},
                          {'name': 'me', 'octet': 3, 'hub': 'hub_us'}], result)

    def test_empty_and_none_hub_use_default(self):
        for hub in ('', None):
            with self.subTest(hub=hub):
                result = plugin.check_clients([{'name': 'x', 'octet': 2, 'hub': hub}], self.t)
                self.assertEqual('hub_de', result[0]['hub'])

    def test_default_hub_follows_topology_default(self):
        t = self.topo(default_hub='hub_us')
        self.assertEqual('hub_us', plugin.check_clients([{'name': 'x', 'octet': 2}], t)[0]['hub'])

    def test_empty_list(self):
        self.assertEqual([], plugin.check_clients([], self.t))

    def test_unknown_hub(self):
        self.assertCode('unknown_hub', plugin.check_clients,
                        [{'name': 'x', 'octet': 2, 'hub': 'hub_fr'}], self.t)

    def test_invalid_hub_type(self):
        for hub in (2, ['hub_us'], True):
            with self.subTest(hub=hub):
                self.assertCode('invalid_client', plugin.check_clients,
                                [{'name': 'x', 'octet': 2, 'hub': hub}], self.t)

    def test_invalid_octet(self):
        for octet in (1, 255, '02', 0, 2.5, True, None, 'x'):
            with self.subTest(octet=octet):
                self.assertCode('invalid_client', plugin.check_clients,
                                [{'name': 'x', 'octet': octet}], self.t)

    def test_octet_boundaries_are_valid(self):
        result = plugin.check_clients([{'name': 'a', 'octet': 2}, {'name': 'b', 'octet': 254}],
                                      self.t)
        self.assertEqual([2, 254], [c['octet'] for c in result])

    def test_invalid_name(self):
        for name in ('', 'a b', '../x', 'a' * 33, 5, None):
            with self.subTest(name=name):
                self.assertCode('invalid_client', plugin.check_clients,
                                [{'name': name, 'octet': 2}], self.t)

    def test_name_with_32_chars_is_valid(self):
        self.assertEqual('a' * 32,
                         plugin.check_clients([{'name': 'a' * 32, 'octet': 2}], self.t)[0]['name'])

    def test_not_mapping_or_not_list(self):
        self.assertCode('invalid_client', plugin.check_clients, ['phone'], self.t)
        self.assertCode('invalid_client', plugin.check_clients, {'name': 'x'}, self.t)
        self.assertCode('invalid_client', plugin.check_clients, 'x', self.t)

    def test_duplicates(self):
        self.assertCode('duplicate_client_name', plugin.check_clients,
                        [{'name': 'x', 'octet': 2}, {'name': 'x', 'octet': 3}], self.t)
        self.assertCode('duplicate_client_octet', plugin.check_clients,
                        [{'name': 'x', 'octet': 2}, {'name': 'y', 'octet': '2'}], self.t)

    def test_input_not_mutated(self):
        clients = [{'name': 'x', 'octet': '2'}]
        plugin.check_clients(clients, self.t)
        self.assertEqual([{'name': 'x', 'octet': '2'}], clients)


class EffectiveClientsTest(PluginCase):
    def setUp(self):
        self.t = self.topo()
        self.clients = [{'name': 'phone', 'octet': 2}, {'name': 'old', 'octet': 5}]
        self.registry = {'clients': [{'name': 'laptop', 'octet': 4, 'public_key': KEY('K')},
                                     {'name': 'me', 'octet': 6, 'public_key': KEY('M'),
                                      'hub': 'hub_us'}],
                         'removed': ['old']}

    def eff(self, clients=None, registry='default'):
        registry = copy.deepcopy(self.registry) if registry == 'default' else registry
        return plugin.effective_clients(copy.deepcopy(self.clients if clients is None else clients),
                                        registry, self.t)

    def test_example(self):
        self.assertEqual({
            'inventory': [{'name': 'phone', 'octet': 2, 'hub': 'hub_de'}],
            'dynamic': [{'name': 'laptop', 'octet': 4, 'public_key': KEY('K'), 'hub': 'hub_de'},
                        {'name': 'me', 'octet': 6, 'public_key': KEY('M'), 'hub': 'hub_us'}],
            'removed': ['old']}, self.eff())

    def test_registry_none_is_empty(self):
        self.assertEqual({'inventory': [{'name': 'phone', 'octet': 2, 'hub': 'hub_de'},
                                        {'name': 'old', 'octet': 5, 'hub': 'hub_de'}],
                          'dynamic': [], 'removed': []}, self.eff(registry=None))

    def test_registry_hub_empty_string_uses_default(self):
        self.registry['clients'][1]['hub'] = ''
        self.assertEqual('hub_de', self.eff()['dynamic'][1]['hub'])

    def test_registry_hub_none_uses_default(self):
        self.registry['clients'][1]['hub'] = None
        self.assertEqual('hub_de', self.eff()['dynamic'][1]['hub'])

    def test_registry_hub_unknown(self):
        self.registry['clients'][1]['hub'] = 'hub_fr'
        self.assertCode('unknown_hub', plugin.effective_clients, self.clients, self.registry, self.t)

    def test_registry_hub_not_string(self):
        self.registry['clients'][1]['hub'] = 7
        self.assertCode('invalid_registry', plugin.effective_clients, self.clients,
                        self.registry, self.t)

    def test_dynamic_octet_clash_with_inventory(self):
        self.registry['clients'][0]['octet'] = 2
        self.assertCode('duplicate_client_octet', plugin.effective_clients, self.clients,
                        self.registry, self.t)

    def test_removed_inventory_client_frees_octet(self):
        self.registry['clients'][0]['octet'] = 5
        result = self.eff()
        self.assertEqual(5, result['dynamic'][0]['octet'])

    def test_inventory_client_shadowed_by_registry_name_is_dropped(self):
        self.registry['clients'].append({'name': 'phone', 'octet': 9, 'public_key': KEY('Q')})
        result = self.eff()
        self.assertEqual([], result['inventory'])
        self.assertEqual('phone', result['dynamic'][-1]['name'])

    def test_duplicate_name_inside_registry(self):
        self.registry['clients'][1]['name'] = 'laptop'
        self.assertCode('duplicate_client_name', plugin.effective_clients, self.clients,
                        self.registry, self.t)

    def test_invalid_registry_shapes(self):
        bad_registries = [
            [], 'x', {'clients': []}, {'removed': []}, {'clients': {}, 'removed': []},
            {'clients': [], 'removed': 'old'},
            {'clients': [], 'removed': ['bad name']},
            {'clients': ['x'], 'removed': []},
            {'clients': [{'name': 'a', 'octet': 4}], 'removed': []},
            {'clients': [{'name': 'a', 'octet': 4, 'public_key': 'short'}], 'removed': []},
            {'clients': [{'name': 'a b', 'octet': 4, 'public_key': KEY('K')}], 'removed': []},
            {'clients': [{'name': 'a', 'octet': 1, 'public_key': KEY('K')}], 'removed': []},
            {'clients': [{'name': 'a', 'octet': 'x', 'public_key': KEY('K')}], 'removed': []},
            {'clients': [{'octet': 4, 'public_key': KEY('K')}], 'removed': []},
        ]
        for reg in bad_registries:
            with self.subTest(registry=reg):
                self.assertCode('invalid_registry', plugin.effective_clients, [], reg, self.t)

    def test_inventory_validated_even_when_removed(self):
        clients = [{'name': 'old', 'octet': 5, 'hub': 'hub_fr'}]
        self.assertCode('unknown_hub', plugin.effective_clients, clients, self.registry, self.t)

    def test_inventory_defects_are_reported(self):
        self.assertCode('invalid_client', plugin.effective_clients, [{'name': 'x', 'octet': 1}],
                        None, self.t)

    def test_removed_is_a_copy(self):
        result = self.eff()
        result['removed'].append('zzz')
        self.assertEqual(['old'], self.registry['removed'])

    def test_inputs_not_mutated(self):
        clients, registry = copy.deepcopy(self.clients), copy.deepcopy(self.registry)
        plugin.effective_clients(clients, registry, self.t)
        self.assertEqual(self.clients, clients)
        self.assertEqual(self.registry, registry)


class RenderBindingsTest(PluginCase):
    HEADER = '# Managed by amneziawg-cascade. Format: <client address> <routing table>\n'

    def test_example(self):
        t = self.topo()
        eff = {'inventory': [{'name': 'phone', 'octet': 2, 'hub': 'hub_de'}],
               'dynamic': [{'name': 'laptop', 'octet': 4, 'public_key': KEY('K'), 'hub': 'hub_de'},
                           {'name': 'me', 'octet': 6, 'public_key': KEY('M'), 'hub': 'hub_us'}],
               'removed': ['old']}
        self.assertEqual(self.HEADER + '10.2.0.2 10010\n10.2.0.4 10010\n10.2.0.6 10020\n',
                         plugin.render_bindings(eff, t))

    def test_empty_lists_give_header_only(self):
        self.assertEqual(self.HEADER, plugin.render_bindings(
            {'inventory': [], 'dynamic': [], 'removed': []}, self.topo()))

    def test_sorted_by_octet_across_inventory_and_dynamic(self):
        eff = {'inventory': [{'name': 'a', 'octet': 100, 'hub': 'hub_us'},
                             {'name': 'b', 'octet': 9, 'hub': 'hub_de'}],
               'dynamic': [{'name': 'c', 'octet': 20, 'public_key': KEY('K'), 'hub': 'hub_us'}],
               'removed': []}
        self.assertEqual(self.HEADER + '10.2.0.9 10010\n10.2.0.20 10020\n10.2.0.100 10020\n',
                         plugin.render_bindings(eff, self.topo()))

    def test_uses_client_subnet_of_topology(self):
        t = self.topo(LEGACY_HUBS, client_subnet='10.5.7')
        eff = {'inventory': [{'name': 'a', 'octet': 2, 'hub': 'hub_de'}], 'dynamic': [],
               'removed': []}
        self.assertEqual(self.HEADER + '10.5.7.2 10010\n', plugin.render_bindings(eff, t))


class SettingsDocumentTest(PluginCase):
    def test_legacy(self):
        t = self.topo(LEGACY_HUBS)
        self.assertEqual({'interface': 'awg0', 'endpoint': '203.0.113.10', 'dns': '1.1.1.1',
                          'client_network': '10.2.0.0/24', 'default_hub': 'hub_de',
                          'stub_table': 10019,
                          'hubs': {'hub_de': {'index': 1, 'interface': 'awg1', 'table': 10010}}},
                         plugin.settings_document(t, 'awg0', '203.0.113.10', '1.1.1.1'))

    def test_two_hubs(self):
        doc = plugin.settings_document(self.topo(), 'awg0', '203.0.113.10', '1.1.1.1')
        self.assertEqual({'hub_de': {'index': 1, 'interface': 'awg1', 'table': 10010},
                          'hub_us': {'index': 2, 'interface': 'awghub2', 'table': 10020}},
                         doc['hubs'])
        self.assertEqual('hub_de', doc['default_hub'])


class CheckInterfacesTest(PluginCase):
    def test_none_previous_is_ok(self):
        self.assertIs(True, plugin.check_interfaces(None, ['awg1', 'awg0']))

    def test_accepted(self):
        cases = [(['awg1', 'awg0'], ['awg1', 'awg0']),
                 (['awg1', 'awg0'], ['awg1', 'awghub2', 'awg0']),
                 (['awg1', 'awghub3', 'awg0'], ['awg1', 'awghub2', 'awghub3', 'awg0']),
                 (['awg2'], ['awg2']), ([], ['awg1'])]
        for prev, cur in cases:
            with self.subTest(previous=prev, current=cur):
                self.assertIs(True, plugin.check_interfaces(prev, cur))

    def test_rejected(self):
        cases = [(['awg1', 'awghub2', 'awg0'], ['awg1', 'awg0']),
                 (['awg1', 'awg0'], ['wgde', 'awg0']),
                 (['awg0', 'awg1'], ['awg1', 'awg0']),
                 ('awg1', ['awg1']), ([1, 2], ['awg1']), ({'a': 1}, ['a'])]
        for prev, cur in cases:
            with self.subTest(previous=prev, current=cur):
                self.assertCode('interfaces_changed', plugin.check_interfaces, prev, cur)

    def test_message_names_missing_interface(self):
        exc = self.assertCode('interfaces_changed', plugin.check_interfaces,
                              ['awg1', 'awghub2', 'awg0'], ['awg1', 'awg0'])
        self.assertIn('awghub2', str(exc))


class FilterModuleTest(PluginCase):
    def test_exact_filter_names(self):
        filters = plugin.FilterModule().filters()
        self.assertEqual({
            'awg_cascade_topology': plugin.build_topology,
            'awg_cascade_links': plugin.link_map,
            'awg_cascade_check_link_keys': plugin.check_link_keys,
            'awg_cascade_check_clients': plugin.check_clients,
            'awg_cascade_effective_clients': plugin.effective_clients,
            'awg_cascade_bindings': plugin.render_bindings,
            'awg_cascade_settings': plugin.settings_document,
            'awg_cascade_check_interfaces': plugin.check_interfaces}, filters)


if __name__ == '__main__':
    unittest.main()
