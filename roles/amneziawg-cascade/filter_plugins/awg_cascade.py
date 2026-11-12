"""Filter plugin amneziawg-cascade: formulas, inventory checks, settings and bindings.

Pure functions: no Ansible import, no disk or environment access, arguments are never
modified, results contain only dict/list/str/int/bool/None. Contract: .orchestra/contracts.md, section 1.

The whole plugin lives in one file on purpose (decision D2): Ansible's plugin loader cannot
import sibling files from filter_plugins/.
"""

import re
from collections.abc import Mapping

__all__ = [
    'CascadeInventoryError',
    'FilterModule',
    'build_topology',
    'check_clients',
    'check_interfaces',
    'check_link_keys',
    'effective_clients',
    'hub_params',
    'link_map',
    'render_bindings',
    'settings_document',
    'stub_table',
]

_NAME_RE = re.compile(r'[A-Za-z0-9_-]{1,32}')
_IFACE_RE = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,14}')
_HOST_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]*')
_PUBKEY_RE = re.compile(r'[A-Za-z0-9+/]{43}=')
_SUBNET_RE = re.compile(r'10\.([0-9]{1,3})\.([0-9]{1,3})')
_INT_RE = re.compile(r'[0-9]+')

_MAX_TABLE = 4294967295
_MIN_TABLE = 10000
_MAX_PORT = 65535
_MAX_INDEX = 64
_BINDINGS_HEADER = '# Managed by amneziawg-cascade. Format: <client address> <routing table>\n'


class CascadeInventoryError(ValueError):
    """Inventory or state defect; ``code`` is one of the codes listed in the contract."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------- primitives

def _parse_int(value):
    """Integer per contract: int (not bool) or digit string without leading zeros; else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str) and _INT_RE.fullmatch(value) and (value == '0' or value[0] != '0'):
        return int(value)
    return None


def _int_in_range(value, low, high):
    number = _parse_int(value)
    if number is None or number < low or number > high:
        return None
    return number


def _is_match(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _is_empty(value):
    return value is None or value == ''


# --------------------------------------------------------------------------- hub formulas

def hub_params(index, settings):
    """Per-hub parameters from the 1-based hub index (formulas: architecture.md)."""
    number = _int_in_range(index, 1, _MAX_INDEX)
    if number is None:
        raise CascadeInventoryError(
            'invalid_index', f'awg_hub_index must be an integer 1..{_MAX_INDEX}, got {index!r}')
    subnet = settings['link_subnet']
    offset = 4 * (number - 1)
    return {
        'index': number,
        'interface': str(settings['link_interface']) if number == 1 else f'awghub{number}',
        'gate_port': int(settings['link_port']) + number - 1,
        'network': f'{subnet}.{offset}/30',
        'hub_address': f'{subnet}.{offset + 1}',
        'gate_address': f'{subnet}.{offset + 2}',
        'table': int(settings['route_table']) + 10 * (number - 1),
    }


def stub_table(settings):
    """Routing table with the unreachable stub route: route_table + 9."""
    return int(settings['route_table']) + 9


# --------------------------------------------------------------------------- topology

def _check_gate_and_hubs(hubs, settings):
    """Counts, names and hosts. Returns the gate (name, host) pair."""
    gates = settings['gates']
    if not isinstance(gates, list) or len(gates) != 1:
        count = len(gates) if isinstance(gates, list) else gates
        raise CascadeInventoryError(
            'gate_count', f'group awg_gate must contain exactly one host, got {count!r}')
    gate = gates[0]
    gate_name, gate_host = str(gate['name']), gate['host']
    if not _is_match(_HOST_RE, gate_host):
        raise CascadeInventoryError(
            'invalid_host', f'ansible_host of gate {gate_name} is not a valid host: {gate_host!r}')
    if not isinstance(hubs, list) or not hubs:
        raise CascadeInventoryError('hub_count', 'group awg_hub must contain at least one host')
    names = set()
    hosts = {gate_host: gate_name}
    for hub in hubs:
        name, host = str(hub['name']), hub['host']
        if name in names:
            raise CascadeInventoryError('duplicate_hub', f'hub {name} is listed more than once')
        names.add(name)
        if name == gate_name:
            raise CascadeInventoryError(
                'hub_is_gate', f'host {name} is in both awg_gate and awg_hub groups')
        if not _is_match(_HOST_RE, host):
            raise CascadeInventoryError(
                'invalid_host', f'ansible_host of hub {name} is not a valid host: {host!r}')
        if host in hosts:
            raise CascadeInventoryError(
                'shared_host', f'hub {name} has the same ansible_host {host} as {hosts[host]}')
        hosts[host] = name
    return gate_name


def _normalize_settings(settings):
    """Validate scalar settings; returns a copy with integers converted to int."""
    cfg = {}
    for key in ('client_subnet', 'link_subnet'):
        match = _SUBNET_RE.fullmatch(settings[key]) if isinstance(settings[key], str) else None
        if match is None or any(str(int(o)) != o or int(o) > 255 for o in match.groups()):
            raise CascadeInventoryError(
                'invalid_subnet', f'awg_{key} must be three octets 10.X.Y, got {settings[key]!r}')
        cfg[key] = settings[key]
    for key in ('client_interface', 'link_interface', 'hub_interface'):
        if not _is_match(_IFACE_RE, settings[key]):
            raise CascadeInventoryError(
                'invalid_interface', f'interface name for {key} is invalid: {settings[key]!r}')
        cfg[key] = str(settings[key])
    for key in ('client_port', 'link_port'):
        port = _int_in_range(settings[key], 1, _MAX_PORT)
        if port is None:
            raise CascadeInventoryError(
                'invalid_port', f'port {key} must be an integer 1..{_MAX_PORT}, got {settings[key]!r}')
        cfg[key] = port
    for key in ('route_table', 'ru_table'):
        table = _int_in_range(settings[key], _MIN_TABLE, _MAX_TABLE)
        if table is None:
            raise CascadeInventoryError(
                'invalid_table',
                f'awg_{key} must be an integer {_MIN_TABLE}..{_MAX_TABLE}, got {settings[key]!r}')
        cfg[key] = table
    return cfg


def _assign_indexes(hubs):
    """Returns [(hub, index)] sorted by index; validates required/valid/unique indexes."""
    if len(hubs) == 1 and _is_empty(hubs[0]['index']):
        return [(hubs[0], 1)]
    pairs = []
    seen = {}
    for hub in hubs:
        raw = hub['index']
        if _is_empty(raw):
            raise CascadeInventoryError(
                'index_required', f'awg_hub_index is required for every hub, missing at {hub["name"]}')
        number = _int_in_range(raw, 1, _MAX_INDEX)
        if number is None:
            raise CascadeInventoryError(
                'invalid_index',
                f'awg_hub_index of {hub["name"]} must be an integer 1..{_MAX_INDEX}, got {raw!r}')
        if number in seen:
            raise CascadeInventoryError(
                'duplicate_index', f'hubs {seen[number]} and {hub["name"]} have the same index {number}')
        seen[number] = hub['name']
        pairs.append((hub, number))
    return sorted(pairs, key=lambda pair: pair[1])


def _build_hub(hub, number, cfg):
    params = hub_params(number, cfg)
    port = _int_in_range(hub['hub_port'], 1, _MAX_PORT)
    if port is None:
        raise CascadeInventoryError(
            'invalid_port', f'awg_hub_port of {hub["name"]} must be an integer 1..{_MAX_PORT}, '
                            f'got {hub["hub_port"]!r}')
    if params['gate_port'] > _MAX_PORT:
        raise CascadeInventoryError(
            'invalid_port', f'gate link port {params["gate_port"]} of hub {hub["name"]} exceeds {_MAX_PORT}')
    if params['table'] > _MAX_TABLE:
        raise CascadeInventoryError(
            'invalid_table', f'routing table {params["table"]} of hub {hub["name"]} exceeds {_MAX_TABLE}')
    params.update({
        'name': str(hub['name']),
        'host': str(hub['host']),
        'public_key': str(hub['public_key']),
        'hub_port': port,
    })
    return params


def _first_duplicate(values):
    seen = set()
    for value in values:
        if value in seen:
            return value
        seen.add(value)
    return None


def _check_collisions(hubs, cfg, stub):
    interfaces = [hub['interface'] for hub in hubs]
    clash = _first_duplicate(interfaces + [cfg['client_interface']])
    if clash is not None:
        raise CascadeInventoryError(
            'interface_collision', f'interface name {clash} is used twice among gate interfaces')
    ports = [hub['gate_port'] for hub in hubs]
    clash = _first_duplicate(ports + [cfg['client_port']])
    if clash is not None:
        raise CascadeInventoryError(
            'port_collision', f'UDP port {clash} is used twice among gate ports')
    tables = [cfg['ru_table'], stub] + [hub['table'] for hub in hubs]
    clash = _first_duplicate(tables)
    if clash is not None:
        raise CascadeInventoryError(
            'table_collision',
            f'routing table {clash} is used twice (awg_ru_table, stub table, hub tables)')
    if _subnet_key(cfg['client_subnet']) == _subnet_key(cfg['link_subnet']):
        raise CascadeInventoryError(
            'network_overlap',
            f'awg_client_subnet and awg_link_subnet are the same network {cfg["client_subnet"]}.0/24')


def _subnet_key(subnet):
    return tuple(int(octet) for octet in subnet.split('.'))


def _pick_default_hub(settings, hubs):
    wanted = settings['default_hub']
    names = [hub['name'] for hub in hubs]
    # ansible-core 2.16 passes YAML null as the string 'None'
    if _is_empty(wanted) or wanted == 'None':
        for hub in hubs:
            if hub['index'] == 1:
                return hub['name']
        raise CascadeInventoryError(
            'default_hub_required', 'awg_default_hub is required when no hub has awg_hub_index 1')
    if not isinstance(wanted, str) or wanted not in names:
        raise CascadeInventoryError(
            'unknown_default_hub', f'awg_default_hub {wanted!r} is not one of the hubs: {names}')
    return str(wanted)


def build_topology(hubs, settings):
    """Validate inventory and compute the whole cascade topology."""
    _check_gate_and_hubs(hubs, settings)
    cfg = _normalize_settings(settings)
    built = [_build_hub(hub, number, cfg) for hub, number in _assign_indexes(hubs)]
    stub = stub_table(cfg)
    if stub > _MAX_TABLE:
        raise CascadeInventoryError(
            'invalid_table', f'stub routing table {stub} exceeds {_MAX_TABLE}')
    _check_collisions(built, cfg, stub)
    return {
        'hubs': built,
        'default_hub': _pick_default_hub(settings, built),
        'stub_table': stub,
        'client_network': f'{cfg["client_subnet"]}.0/24',
        'link_network': f'{cfg["link_subnet"]}.0/24',
        'gate_interfaces': [hub['interface'] for hub in built] + [cfg['client_interface']],
    }


# --------------------------------------------------------------------------- links and keys

def link_map(topology, role, hostname, hub_interface):
    """Interface name -> hub parameters for the given node."""
    if role == 'gate':
        return {hub['interface']: dict(hub) for hub in topology['hubs']}
    if role == 'hub':
        for hub in topology['hubs']:
            if hub['name'] == hostname:
                return {hub_interface: dict(hub)}
        raise CascadeInventoryError(
            'unknown_host', f'host {hostname} is not in the awg_hub group of the topology')
    raise ValueError(f'unknown role: {role!r}')


def check_link_keys(topology, gate_public_key):
    """Link public keys are well-formed and pairwise distinct; returns True."""
    if not _is_match(_PUBKEY_RE, gate_public_key):
        raise CascadeInventoryError('invalid_key', 'public key of the gate link is not a valid key')
    owners = {gate_public_key: 'gate'}
    for hub in topology['hubs']:
        key = hub['public_key']
        if not _is_match(_PUBKEY_RE, key):
            raise CascadeInventoryError(
                'invalid_key',
                f'awg_hub_link_public_key of hub {hub["name"]} is empty or not a valid key')
        if key in owners:
            raise CascadeInventoryError(
                'duplicate_key',
                f'hub {hub["name"]} has the same link public key as {owners[key]}; '
                f'set awg_hub_link_public_key per hub')
        owners[key] = hub['name']
    return True


# --------------------------------------------------------------------------- clients

def _client_hub(entry, topology, error_code, label):
    """Hub name of a client entry (inventory or registry) with the default substituted."""
    hub = entry.get('hub')
    if _is_empty(hub):
        return topology['default_hub']
    if not isinstance(hub, str):
        raise CascadeInventoryError(error_code, f'{label}: hub must be a string, got {hub!r}')
    if hub not in {item['name'] for item in topology['hubs']}:
        raise CascadeInventoryError('unknown_hub', f'{label}: hub {hub} is not in the topology')
    return str(hub)


def _client_basics(entry, error_code, label):
    """Validated (name, octet) of a mapping entry."""
    if not isinstance(entry, Mapping):
        raise CascadeInventoryError(error_code, f'{label}: entry must be a mapping, got {entry!r}')
    name = entry.get('name')
    if not _is_match(_NAME_RE, name):
        raise CascadeInventoryError(error_code, f'{label}: invalid client name {name!r}')
    octet = _int_in_range(entry.get('octet'), 2, 254)
    if octet is None:
        raise CascadeInventoryError(
            error_code, f'{label}: octet of client {name} must be an integer 2..254, '
                        f'got {entry.get("octet")!r}')
    return str(name), octet


def _check_unique(items, label):
    """Names and octets of normalized clients must be unique."""
    names = set()
    octets = {}
    for item in items:
        if item['name'] in names:
            raise CascadeInventoryError(
                'duplicate_client_name', f'{label}: client name {item["name"]} is used twice')
        names.add(item['name'])
        if item['octet'] in octets:
            raise CascadeInventoryError(
                'duplicate_client_octet',
                f'{label}: octet {item["octet"]} is used by {octets[item["octet"]]} and {item["name"]}')
        octets[item['octet']] = item['name']


def check_clients(clients, topology):
    """Validate awg_clients; returns normalized [{'name', 'octet', 'hub'}]."""
    label = 'awg_clients'
    if not isinstance(clients, list):
        raise CascadeInventoryError('invalid_client', f'{label} must be a list, got {clients!r}')
    result = []
    for entry in clients:
        name, octet = _client_basics(entry, 'invalid_client', label)
        hub = _client_hub(entry, topology, 'invalid_client', f'{label} {name}')
        result.append({'name': name, 'octet': octet, 'hub': hub})
    _check_unique(result, label)
    return result


def _check_registry(registry, topology):
    label = 'cascade-clients.json'
    if (not isinstance(registry, Mapping) or not isinstance(registry.get('clients'), list)
            or not isinstance(registry.get('removed'), list)):
        raise CascadeInventoryError(
            'invalid_registry', f'{label} must be an object with lists "clients" and "removed"')
    dynamic = []
    for entry in registry['clients']:
        name, octet = _client_basics(entry, 'invalid_registry', label)
        if not _is_match(_PUBKEY_RE, entry.get('public_key')):
            raise CascadeInventoryError(
                'invalid_registry', f'{label}: client {name} has no valid public_key')
        hub = _client_hub(entry, topology, 'invalid_registry', f'{label} {name}')
        dynamic.append({'name': name, 'octet': octet, 'public_key': str(entry['public_key']), 'hub': hub})
    for name in registry['removed']:
        if not _is_match(_NAME_RE, name):
            raise CascadeInventoryError(
                'invalid_registry', f'{label}: invalid name in "removed": {name!r}')
    names = set()
    for item in dynamic:
        if item['name'] in names:
            raise CascadeInventoryError(
                'duplicate_client_name', f'{label}: client name {item["name"]} is used twice')
        names.add(item['name'])
    return dynamic, [str(name) for name in registry['removed']]


def effective_clients(clients, registry, topology):
    """Merge inventory and registry clients: {'inventory', 'dynamic', 'removed'}."""
    normalized = check_clients(clients, topology)
    if registry is None:
        registry = {'clients': [], 'removed': []}
    dynamic, removed = _check_registry(registry, topology)
    skipped = set(removed) | {item['name'] for item in dynamic}
    inventory = [item for item in normalized if item['name'] not in skipped]
    _check_unique(inventory + dynamic, 'inventory and cascade-clients.json')
    return {'inventory': inventory, 'dynamic': dynamic, 'removed': removed}


def render_bindings(effective, topology):
    """Text of cascade-bindings.list: '<address> <table>' per client, ascending octet."""
    prefix = topology['client_network'].split('/')[0].rsplit('.', 1)[0]
    tables = {hub['name']: hub['table'] for hub in topology['hubs']}
    clients = sorted(effective['inventory'] + effective['dynamic'], key=lambda item: int(item['octet']))
    lines = [f'{prefix}.{int(item["octet"])} {tables[item["hub"]]}\n' for item in clients]
    return _BINDINGS_HEADER + ''.join(lines)


# --------------------------------------------------------------------------- settings, interfaces

def settings_document(topology, client_interface, endpoint, dns):
    """Content of cascade-settings.json (format v2)."""
    return {
        'interface': client_interface,
        'endpoint': endpoint,
        'dns': dns,
        'client_network': topology['client_network'],
        'default_hub': topology['default_hub'],
        'stub_table': topology['stub_table'],
        'hubs': {
            hub['name']: {'index': hub['index'], 'interface': hub['interface'], 'table': hub['table']}
            for hub in topology['hubs']
        },
    }


def _is_subsequence(previous, current):
    remaining = iter(current)
    return all(any(item == candidate for candidate in remaining) for item in previous)


def check_interfaces(previous, current):
    """The saved interface list must be a subsequence of the new one (hubs can only be added)."""
    if previous is None:
        return True
    if not isinstance(previous, list) or not all(isinstance(item, str) for item in previous):
        raise CascadeInventoryError(
            'interfaces_changed',
            f'saved /var/lib/awg-cascade/interfaces.json is not a list of strings: {previous!r}; see README')
    if _is_subsequence(previous, current):
        return True
    missing = [item for item in previous if item not in current]
    detail = f'missing interfaces: {missing}' if missing else 'interface order changed'
    raise CascadeInventoryError(
        'interfaces_changed',
        f'interfaces of the previous run {previous} are not a subsequence of {list(current)} ({detail}); '
        f'removing or renaming hubs is manual, see README')


class FilterModule:
    """Ansible filter plugin entry point."""

    def filters(self):
        return {
            'awg_cascade_topology': build_topology,
            'awg_cascade_links': link_map,
            'awg_cascade_check_link_keys': check_link_keys,
            'awg_cascade_check_clients': check_clients,
            'awg_cascade_effective_clients': effective_clients,
            'awg_cascade_bindings': render_bindings,
            'awg_cascade_settings': settings_document,
            'awg_cascade_check_interfaces': check_interfaces,
        }
