#!/usr/bin/env python3
"""Manage gate peers without restarting tunnels. Registry contains public data only."""
import argparse
import base64
import binascii
from dataclasses import dataclass, field
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

__all__ = ['NAME', 'SYNC_COMMAND', 'awg', 'sync_rules', 'atomic', 'fields', 'peer_blocks',
           'parse_bindings', 'render_bindings', 'recover', 'manage', 'main']

NAME = re.compile(r'[A-Za-z0-9_-]{1,32}\Z')
IFACE = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,14}\Z')
BINDING_LINE = re.compile(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3}) ([0-9]{1,10})')
BINDINGS_HEADER = '# Managed by amneziawg-cascade. Format: <client address> <routing table>\n'
SYNC_COMMAND = '/usr/local/sbin/awg-cascade-rules'
OBFUSCATION = re.compile(r'MTU|Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RandomTrailers|DisableCookies')
BAD_BINDINGS = 'Client routing state is missing or corrupt; run gate.yml'
BAD_SETTINGS = 'Invalid saved settings; run gate.yml'


def awg(*args, input=None):
    return subprocess.run(['awg', *args], input=input, text=True, capture_output=True, check=True).stdout.strip()


def sync_rules(base):
    subprocess.run([SYNC_COMMAND, '--config-dir', str(base)], text=True, capture_output=True, check=True)


def atomic(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        temp = Path(f.name)
        try:
            f.write(data); f.flush(); os.fsync(f.fileno())
            f.close()
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)


def read_text(path):
    return path.read_bytes().decode('utf-8')


def read_json(path):
    return json.loads(read_text(path))


def warn(message):
    print(message, file=sys.stderr)


def fields(text):
    result = {}
    for line in text.splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            result[key.strip()] = value.strip()
    return result


def peer_blocks(config):
    chunks = re.split(r'^\[Peer\][^\n]*\n', config, flags=re.M)
    peers = []
    for body in chunks[1:]:
        values = fields(body)
        match = re.search(r'^# ([A-Za-z0-9_-]{1,32})\s*$', body, re.M)
        peers.append({'name': match[1] if match else '(unnamed)', 'body': body, **values})
    return chunks[0], peers


# ---- settings and bindings -------------------------------------------------

def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def valid_network(value):
    if not isinstance(value, str):
        return False
    try:
        network = ipaddress.ip_network(value)
    except ValueError:
        return False
    return isinstance(network, ipaddress.IPv4Network) and network.prefixlen == 24 and str(network) == value


def settings_v2_valid(settings):
    hubs = settings['hubs']
    if not isinstance(hubs, dict) or not hubs:
        return False
    if not all(isinstance(h, dict) and is_int(h.get('table')) for h in hubs.values()):
        return False
    stub = settings.get('stub_table')
    return (settings.get('default_hub') in hubs and valid_network(settings.get('client_network'))
            and is_int(stub) and stub not in {h['table'] for h in hubs.values()})


def load_settings(base):
    """Return (settings, v2); legacy settings have no 'hubs' key."""
    settings = read_json(base/'cascade-settings.json')
    interface = settings['interface']
    if not isinstance(interface, str) or not IFACE.fullmatch(interface):
        raise ValueError('Invalid saved interface')
    v2 = 'hubs' in settings
    if v2 and not settings_v2_valid(settings):
        raise ValueError(BAD_SETTINGS)
    return settings, v2


def parse_bindings(text, network, tables):
    """Parse bindings text (contracts section 2.2) into {address: table}; ValueError if corrupt."""
    result = {}
    for line in text.split('\n'):
        if line == '' or line.startswith('#'):
            continue
        match = BINDING_LINE.fullmatch(line)
        if not match:
            raise ValueError('bad binding line')
        addr, table = match[1], int(match[2])
        try:
            parsed = ipaddress.IPv4Address(addr)
        except ValueError as exc:
            raise ValueError('bad binding address') from exc
        if str(parsed) != addr or parsed not in network or not 2 <= int(addr.rsplit('.', 1)[1]) <= 254:
            raise ValueError('bad binding address')
        if table not in tables or addr in result:
            raise ValueError('bad binding table or duplicate address')
        result[addr] = table
    return result


def render_bindings(bindings):
    lines = sorted(bindings.items(), key=lambda item: ipaddress.IPv4Address(item[0]))
    return BINDINGS_HEADER + ''.join(f'{addr} {table}\n' for addr, table in lines)


def load_bindings(base, settings):
    """Read and validate the bindings file; ValueError (generic message) if absent or corrupt."""
    tables = {h['table'] for h in settings['hubs'].values()}
    try:
        text = read_text(base/'cascade-bindings.list')
        return parse_bindings(text, ipaddress.ip_network(settings['client_network']), tables)
    except (OSError, ValueError) as exc:
        raise ValueError(BAD_BINDINGS) from exc


# ---- journal and recovery --------------------------------------------------

def valid_step(step):
    if step == ['sync-rules']:
        return True
    return (isinstance(step, list) and len(step) >= 3 and all(isinstance(s, str) for s in step)
            and step[0] == 'awg' and step[1] == 'set')


def valid_rel_path(rel):
    if not isinstance(rel, str) or not rel or rel[0] in '/\\' or '\\' in rel or ':' in rel:
        return False
    return '..' not in rel.split('/')


def decode_previous(previous):
    if not isinstance(previous, dict):
        raise ValueError('Unreadable transaction journal')
    result = {}
    for rel, data in previous.items():
        if not valid_rel_path(rel) or not (data is None or isinstance(data, str)):
            raise ValueError('Unreadable transaction journal')
        try:
            result[rel] = None if data is None else base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError('Unreadable transaction journal') from exc
    return result


def parse_journal(path):
    """Return (steps, previous) from a v2 or v1 journal; ValueError if unreadable."""
    data = read_json(path)
    if not isinstance(data, dict) or 'previous' not in data or 'undo' not in data:
        raise ValueError('Unreadable transaction journal')
    undo = data['undo']
    if 'version' in data:
        if not is_int(data['version']) or data['version'] != 2 or not isinstance(undo, list) \
                or not all(valid_step(s) for s in undo):
            raise ValueError('Unreadable transaction journal')
        steps = undo
    else:
        if not isinstance(undo, list) or not undo or not all(isinstance(s, str) for s in undo) or undo[0] != 'set':
            raise ValueError('Unreadable transaction journal')
        steps = [['awg', *undo]]
    return steps, decode_previous(data['previous'])


def restore_files(base, previous):
    """Strict: any failure propagates. previous maps relative POSIX path to bytes or None."""
    for rel, data in previous.items():
        path = base/rel
        if data is None:
            path.unlink(missing_ok=True)
        else:
            atomic(path, data)


def run_step(base, step):
    if step[0] == 'sync-rules':
        sync_rules(base)
    else:
        awg(*step[1:])


def recover_step(base, step):
    if step[0] == 'sync-rules':
        try:
            sync_rules(base)
        except Exception as exc:  # best effort: the next sync (hook or gate.yml) rebuilds rules
            warn(f'Warning: recovery step sync-rules failed: {type(exc).__name__}')
        return
    interface = step[2]
    try:
        running = awg('show', interface, 'public-key')
    except Exception:  # interface down or awg unavailable: skip, config applies on start
        running = ''
    if running in ('', '(none)'):
        warn(f'Warning: interface {interface} is not running; skipped awg step')
    else:
        awg(*step[1:])


def recover(base):
    journal = base/'.cascade-client-transaction.json'
    if not journal.exists():
        return
    steps, previous = parse_journal(journal)
    restore_files(base, previous)
    for step in steps:
        recover_step(base, step)
    journal.unlink()


# ---- planning --------------------------------------------------------------

@dataclass
class Context:
    base: Path
    settings: dict
    v2: bool
    interface: str
    config_path: Path
    original: str
    header: str
    peers: list
    bindings: dict | None = None


@dataclass
class Plan:
    updates: dict = field(default_factory=dict)  # Path -> bytes | None
    apply: list = field(default_factory=list)
    undo: list = field(default_factory=list)
    result: str = ''


def load_context(base, settings, v2):
    interface = settings['interface']
    config_path = base/f'{interface}.conf'
    original = read_text(config_path)
    header, peers = peer_blocks(original)
    return Context(base, settings, v2, interface, config_path, original, header, peers)


def load_registry(base):
    path = base/'cascade-clients.json'
    registry = read_json(path) if path.exists() else {'clients': [], 'removed': []}
    return path, registry


def resolve_hub(settings, hub):
    target = settings['default_hub'] if hub is None else hub
    if target not in settings['hubs']:
        raise ValueError(f'Unknown hub: {target}')
    return target


def free_address(values, peers):
    subnet = ipaddress.IPv4Interface(values['Address']).network
    if subnet.prefixlen != 24:
        raise ValueError('Expected /24 client subnet')
    used = [ipaddress.ip_network(c.strip()) for p in peers for c in p['AllowedIPs'].split(',')]
    ip = next((subnet.network_address + n for n in range(2, 255)
               if not any(subnet.network_address + n in net for net in used)), None)
    if ip is None:
        raise ValueError('No free client address')
    return ip


def generate_keys(peers):
    private = awg('genkey')
    public = awg('pubkey', input=private+'\n')
    if any(p.get('PublicKey') == public for p in peers):
        raise ValueError('Generated public key already registered')
    return private, public


def client_profile(ctx, values, ip, private, server_public):
    settings = ctx.settings
    obfuscation = '\n'.join(f'{k} = {v}' for k, v in values.items() if OBFUSCATION.fullmatch(k))
    return (f'[Interface]\nPrivateKey = {private}\nAddress = {ip}/32\nDNS = {settings["dns"]}\n'
            f'{obfuscation}\n\n[Peer]\nPublicKey = {server_public}\n'
            f'Endpoint = {settings["endpoint"]}:{values["ListenPort"]}\n'
            'AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n')


def plan_add(ctx, name, hub_name):
    base, interface = ctx.base, ctx.interface
    if any(p['name'] == name for p in ctx.peers):
        raise ValueError('Client already exists')
    values = fields(ctx.header)
    ip = free_address(values, ctx.peers)
    private, public = generate_keys(ctx.peers)
    server_public = awg('show', interface, 'public-key')
    if not server_public or server_public == '(none)':
        raise ValueError('Client interface is not running')
    registry_path, registry = load_registry(base)
    entry = {'name': name, 'octet': int(str(ip).split('.')[-1]), 'public_key': public}
    if ctx.v2:
        entry['hub'] = hub_name
    registry['clients'] = [p for p in registry['clients'] if p['name'] != name] + [entry]
    registry['removed'] = [n for n in registry['removed'] if n != name]
    profile = base/'cascade-clients'/f'{name}.conf'
    plan = Plan(result=str(profile))
    plan.updates[base/'cascade-keys'/f'client-{name}.key'] = (private+'\n').encode('utf-8')
    plan.updates[profile] = client_profile(ctx, values, ip, private, server_public).encode('utf-8')
    config = ctx.original.rstrip()+f'\n\n[Peer]\n# {name}\nPublicKey = {public}\nAllowedIPs = {ip}/32\n'
    plan.updates[ctx.config_path] = config.encode('utf-8')
    plan.updates[registry_path] = (json.dumps(registry, indent=2)+'\n').encode('utf-8')
    set_peer = ['awg', 'set', interface, 'peer', public, 'allowed-ips', f'{ip}/32']
    drop_peer = ['awg', 'set', interface, 'peer', public, 'remove']
    if ctx.v2:
        bindings = dict(ctx.bindings)
        bindings[str(ip)] = ctx.settings['hubs'][hub_name]['table']
        plan.updates[base/'cascade-bindings.list'] = render_bindings(bindings).encode('utf-8')
        plan.apply, plan.undo = [['sync-rules'], set_peer], [drop_peer, ['sync-rules']]
    else:
        plan.apply, plan.undo = [set_peer], [drop_peer]
    return plan


def peer_addresses(allowed):
    return [c.strip()[:-3] for c in allowed.split(',') if c.strip().endswith('/32')]


def plan_remove(ctx, name):
    base, interface = ctx.base, ctx.interface
    matching = [p for p in ctx.peers if p['name'] == name]
    if len(matching) != 1:
        raise ValueError('Client not found or duplicate client names')
    public, allowed = matching[0]['PublicKey'], matching[0]['AllowedIPs']
    registry_path, registry = load_registry(base)
    registry['clients'] = [p for p in registry['clients'] if p['name'] != name]
    registry['removed'] = sorted(set(registry['removed'] + [name]))
    plan = Plan(result=f'Removed: {name}')
    plan.updates[base/'cascade-clients'/f'{name}.conf'] = None
    plan.updates[base/'cascade-keys'/f'client-{name}.key'] = None
    config = ctx.header+''.join('[Peer]\n'+p['body'] for p in ctx.peers if p['name'] != name)
    plan.updates[ctx.config_path] = config.encode('utf-8')
    plan.updates[registry_path] = (json.dumps(registry, indent=2)+'\n').encode('utf-8')
    drop_peer = ['awg', 'set', interface, 'peer', public, 'remove']
    restore_peer = ['awg', 'set', interface, 'peer', public, 'allowed-ips', allowed]
    if ctx.v2:
        gone = set(peer_addresses(allowed))
        bindings = {a: t for a, t in ctx.bindings.items() if a not in gone}
        plan.updates[base/'cascade-bindings.list'] = render_bindings(bindings).encode('utf-8')
        plan.apply, plan.undo = [drop_peer, ['sync-rules']], [['sync-rules'], restore_peer]
    else:
        plan.apply, plan.undo = [drop_peer], [restore_peer]
    return plan


# ---- transaction -----------------------------------------------------------

def write_journal(base, journal, plan):
    previous = {}
    for path in plan.updates:
        previous[path.relative_to(base).as_posix()] = path.read_bytes() if path.exists() else None
    document = {'version': 2, 'undo': plan.undo, 'previous': {
        rel: base64.b64encode(data).decode('ascii') if data is not None else None
        for rel, data in previous.items()}}
    atomic(journal, json.dumps(document).encode('utf-8'))
    return previous


def rollback(base, journal, previous, undo):
    """Restore files strictly; on failure keep the journal for recover(). Then undo steps best-effort."""
    try:
        restore_files(base, previous)
    except Exception as exc:  # the journal stays; recover() finishes the restoration
        warn(f'Warning: rollback could not restore files: {type(exc).__name__}; run list-clients.sh')
        return
    for step in undo:
        try:
            run_step(base, step)
        except Exception as exc:  # one failed step must not stop the others
            warn(f'Warning: rollback step {step[0]} failed: {type(exc).__name__}')
    journal.unlink(missing_ok=True)


def execute(base, plan):
    journal = base/'.cascade-client-transaction.json'
    previous = write_journal(base, journal, plan)
    try:
        for path, data in plan.updates.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                atomic(path, data)
        for step in plan.apply:
            run_step(base, step)
    except Exception:
        rollback(base, journal, previous, plan.undo)
        raise
    journal.unlink()


# ---- commands --------------------------------------------------------------

def print_list(ctx):
    table_hub = {}
    if ctx.v2:
        table_hub = {h['table']: n for n, h in ctx.settings['hubs'].items()}
        try:
            ctx.bindings = load_bindings(ctx.base, ctx.settings)
        except ValueError:
            ctx.bindings = None
    print('NAME\tADDRESS\tHUB\tPUBLIC KEY')
    for peer in ctx.peers:
        allowed = peer.get('AllowedIPs', '')
        print(f"{peer['name']}\t{allowed}\t{hub_label(ctx, table_hub, allowed)}\t{peer.get('PublicKey', '')}")


def hub_label(ctx, table_hub, allowed):
    if not ctx.v2:
        return '-'
    if ctx.bindings is None:
        return '?'
    addresses = [c.strip() for c in allowed.split(',')]
    if len(addresses) != 1 or not addresses[0].endswith('/32'):
        return '-'
    return table_hub.get(ctx.bindings.get(addresses[0][:-3]), '-')


def validate_args(action, name, hub):
    if action != 'list' and (not name or not NAME.fullmatch(name)):
        raise ValueError('Name: 1–32 Latin letters, digits, underscore or hyphen')
    if action not in ('add', 'remove', 'list'):
        raise ValueError('Unknown action')
    if hub is not None and action != 'add':
        raise ValueError('--hub is only valid with add')


def manage(base, action, name=None, hub=None):
    base = Path(base)
    validate_args(action, name, hub)
    with (base/'.cascade-clients.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action != 'list' and (base/'.cascade-deploy').exists():
            raise ValueError('gate.yml is running; retry after deployment finishes')
        settings, v2 = load_settings(base)
        if hub is not None and not v2:
            raise ValueError('Choosing a hub requires updated settings; run gate.yml')
        recover(base)
        ctx = load_context(base, settings, v2)
        if action == 'list':
            print_list(ctx)
            return
        hub_name = resolve_hub(settings, hub) if v2 and action == 'add' else None
        if v2:
            ctx.bindings = load_bindings(base, settings)
        plan = plan_add(ctx, name, hub_name) if action == 'add' else plan_remove(ctx, name)
        execute(base, plan)
        print(plan.result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['add', 'remove', 'list'])
    parser.add_argument('name', nargs='?')
    parser.add_argument('--hub', help='hub for the new client (add only)')
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Run as root or with sudo')
    os.umask(0o077)
    try:
        manage(Path(os.environ.get('AWG_CONFIG_DIR', '/etc/amnezia/amneziawg')), args.action, args.name, args.hub)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        # Do not print subprocess stderr: it may include configuration material.
        parser.exit(1, f'Error: {type(exc).__name__}: operation failed; verify client name, settings and running AWG interface\n'
                    if isinstance(exc, subprocess.CalledProcessError) else f'Error: {exc}\n')


if __name__ == '__main__': main()
