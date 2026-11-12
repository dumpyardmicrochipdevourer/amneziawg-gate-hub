"""Shared helpers for the tests: module loading, fcntl stub, reference data (contracts.md)."""
from pathlib import Path
import importlib.util
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
GOLDEN = TESTS / 'golden'
ROLE = 'roles/amneziawg-cascade'


def install_fcntl_stub():
    if 'fcntl' not in sys.modules:
        try:
            import fcntl  # noqa: F401
        except ImportError:
            sys.modules['fcntl'] = types.SimpleNamespace(
                LOCK_EX=2, LOCK_NB=4, flock=lambda fd, op: None)


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_plugin():
    return load('awg_cascade', ROLE + '/filter_plugins/awg_cascade.py')


def load_rules():
    install_fcntl_stub()
    return load('cascade_rules', ROLE + '/files/cascade_rules.py')


def load_clients():
    install_fcntl_stub()
    return load('cascade_clients', ROLE + '/files/cascade_clients.py')


def golden(name):
    return (GOLDEN / name).read_bytes()


def KEY(c):
    return c * 43 + '='


LEGACY_SETTINGS = {
    'gates': [{'name': 'gate_ru', 'host': '203.0.113.10'}],
    'client_interface': 'awg0', 'client_port': 51820, 'client_subnet': '10.2.0',
    'link_interface': 'awg1', 'link_port': 51822, 'link_subnet': '10.78.0',
    'hub_interface': 'awg2', 'route_table': 10010, 'ru_table': 10011, 'default_hub': None}
LEGACY_HUBS = [{'name': 'hub_de', 'host': '203.0.113.20', 'index': None,
                'public_key': KEY('D'), 'hub_port': 51821}]
TWO_HUBS = [{'name': 'hub_us', 'host': '198.51.100.30', 'index': 2,
             'public_key': KEY('U'), 'hub_port': 51821},
            {'name': 'hub_de', 'host': '203.0.113.20', 'index': 1,
             'public_key': KEY('D'), 'hub_port': 51821}]

HUB_DE = {'name': 'hub_de', 'host': '203.0.113.20', 'public_key': KEY('D'), 'hub_port': 51821,
          'index': 1, 'interface': 'awg1', 'gate_port': 51822, 'network': '10.78.0.0/30',
          'hub_address': '10.78.0.1', 'gate_address': '10.78.0.2', 'table': 10010}
HUB_US = {'name': 'hub_us', 'host': '198.51.100.30', 'public_key': KEY('U'), 'hub_port': 51821,
          'index': 2, 'interface': 'awghub2', 'gate_port': 51823, 'network': '10.78.0.4/30',
          'hub_address': '10.78.0.5', 'gate_address': '10.78.0.6', 'table': 10020}

VARS = dict(
    awg_client_interface='awg0', awg_hub_interface='awg2', awg_client_port=51820,
    awg_client_subnet='10.2.0', awg_mtu=1280, awg_dns='1.1.1.1', awg_ru_table=10011,
    awg_ru_split=True,
    awg_entry_obfuscation={'Jc': 4, 'Jmin': 40, 'Jmax': 70, 'S1': 30, 'S2': 40, 'H1': 1234567891,
                           'H2': 1234567892, 'H3': 1234567893, 'H4': 1234567894},
    awg_link_obfuscation={'Jc': 6, 'Jmin': 8, 'Jmax': 80, 'S1': 21, 'S2': 126, 'H1': 664839111,
                          'H2': 1485638111, 'H3': 1457145111, 'H4': 1956374111},
    awg_clients=[{'name': 'phone', 'octet': 2}, {'name': 'tablet', 'octet': 3},
                 {'name': 'oldphone', 'octet': 5}],
    awg_dynamic_clients=[{'name': 'laptop', 'octet': 4, 'public_key': KEY('K')}],
    awg_removed_clients=['oldphone'],
    awg_private_keys={'entry': 'entry-private-key', 'link': 'link-private-key',
                      'client-phone': 'phone-private-key', 'client-laptop': 'laptop-private-key'},
    awg_public_keys={'entry': KEY('E'), 'link': KEY('G'), 'client-phone': KEY('P'),
                     'client-tablet': KEY('T')},
    awg_gate_link_public_key=KEY('G'), hostvars={'gate_ru': {'ansible_host': '203.0.113.10'}},
    awg_gate='gate_ru', awg_wan='eth0', awg_gateway='203.0.113.1')
