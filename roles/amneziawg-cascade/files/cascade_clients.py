#!/usr/bin/env python3
"""Manage gate peers without restarting tunnels. Registry contains public data only."""
import argparse
import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

NAME = re.compile(r'[A-Za-z0-9_-]{1,32}\Z')


def awg(*args, input=None):
    return subprocess.run(['awg', *args], input=input, text=True, capture_output=True, check=True).stdout.strip()


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


def recover(base):
    journal = base/'.cascade-client-transaction.json'
    if not journal.exists():
        return
    transaction = json.loads(journal.read_text())
    for name, data in transaction['previous'].items():
        path = base/name
        if data is None: path.unlink(missing_ok=True)
        else: atomic(path, base64.b64decode(data))
    awg(*transaction['undo'])
    journal.unlink()


def manage(base, action, name=None):
    base = Path(base)
    if action != 'list' and (not name or not NAME.fullmatch(name)):
        raise ValueError('Name: 1–32 Latin letters, digits, underscore or hyphen')
    with (base/'.cascade-clients.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action != 'list' and (base/'.cascade-deploy').exists():
            raise ValueError('gate.yml is running; retry after deployment finishes')
        settings = json.loads((base/'cascade-settings.json').read_text())
        interface = settings['interface']
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}', interface):
            raise ValueError('Invalid saved interface')
        recover(base)
        path = base/f'{interface}.conf'
        original = path.read_text()
        header, peers = peer_blocks(original)
        if action == 'list':
            print('NAME\tADDRESS\tPUBLIC KEY')
            for peer in peers:
                print(f"{peer['name']}\t{peer.get('AllowedIPs', '')}\t{peer.get('PublicKey', '')}")
            return
        registry_path = base/'cascade-clients.json'
        registry = json.loads(registry_path.read_text()) if registry_path.exists() else {'clients': [], 'removed': []}
        matching = [p for p in peers if p['name'] == name]
        profile = base/'cascade-clients'/f'{name}.conf'
        keyfile = base/'cascade-keys'/f'client-{name}.key'
        updates = {}
        if action == 'add':
            if matching:
                raise ValueError('Client already exists')
            values = fields(header)
            subnet = ipaddress.IPv4Interface(values['Address']).network
            if subnet.prefixlen != 24:
                raise ValueError('Expected /24 client subnet')
            used = [ipaddress.ip_network(c.strip()) for p in peers for c in p['AllowedIPs'].split(',')]
            ip = next((subnet.network_address + n for n in range(2, 255)
                       if not any(subnet.network_address + n in net for net in used)), None)
            if ip is None:
                raise ValueError('No free client address')
            private = awg('genkey')
            public = awg('pubkey', input=private+'\n')
            if any(p.get('PublicKey') == public for p in peers):
                raise ValueError('Generated public key already registered')
            server_public = awg('show', interface, 'public-key')
            if not server_public or server_public == '(none)':
                raise ValueError('Client interface is not running')
            obfuscation = '\n'.join(f'{k} = {v}' for k, v in values.items()
                if re.fullmatch(r'MTU|Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RandomTrailers|DisableCookies', k))
            client = (f'[Interface]\nPrivateKey = {private}\nAddress = {ip}/32\nDNS = {settings["dns"]}\n'
                      f'{obfuscation}\n\n[Peer]\nPublicKey = {server_public}\n'
                      f'Endpoint = {settings["endpoint"]}:{values["ListenPort"]}\n'
                      'AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n')
            updates[keyfile] = (private+'\n').encode()
            updates[profile] = client.encode()
            config = original.rstrip()+f'\n\n[Peer]\n# {name}\nPublicKey = {public}\nAllowedIPs = {ip}/32\n'
            registry['clients'] = [p for p in registry['clients'] if p['name'] != name]
            registry['clients'].append({'name': name, 'octet': int(str(ip).split('.')[-1]), 'public_key': public})
            registry['removed'] = [n for n in registry['removed'] if n != name]
            command = ('set', interface, 'peer', public, 'allowed-ips', f'{ip}/32')
        elif action == 'remove':
            if len(matching) != 1:
                raise ValueError('Client not found or duplicate client names')
            public = matching[0]['PublicKey']
            config = header+''.join('[Peer]\n'+p['body'] for p in peers if p['name'] != name)
            registry['clients'] = [p for p in registry['clients'] if p['name'] != name]
            registry['removed'] = sorted(set(registry['removed'] + [name]))
            updates[profile] = None
            updates[keyfile] = None
            command = ('set', interface, 'peer', public, 'remove')
        else:
            raise ValueError('Unknown action')
        updates[path] = config.encode()
        updates[registry_path] = (json.dumps(registry, indent=2)+'\n').encode()
        previous = {p: p.read_bytes() if p.exists() else None for p in updates}
        journal = base/'.cascade-client-transaction.json'
        undo = (('set', interface, 'peer', public, 'remove') if action == 'add'
                else ('set', interface, 'peer', public, 'allowed-ips', matching[0]['AllowedIPs']))
        atomic(journal, json.dumps({'undo': undo, 'previous': {
            str(p.relative_to(base)): base64.b64encode(data).decode() if data is not None else None
            for p, data in previous.items()}}).encode())
        try:
            for p, data in updates.items():
                if data is None: p.unlink(missing_ok=True)
                else: atomic(p, data)
            awg(*command)
            journal.unlink()
        except Exception:
            for p, data in previous.items():
                if data is None: p.unlink(missing_ok=True)
                else: atomic(p, data)
            journal.unlink(missing_ok=True)
            raise
        print(profile if action == 'add' else f'Removed: {name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['add', 'remove', 'list'])
    parser.add_argument('name', nargs='?')
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Run as root or with sudo')
    os.umask(0o077)
    try:
        manage(Path(os.environ.get('AWG_CONFIG_DIR', '/etc/amnezia/amneziawg')), args.action, args.name)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        # Do not print subprocess stderr: it may include configuration material.
        parser.exit(1, f'Error: {type(exc).__name__}: operation failed; verify client name, settings and running AWG interface\n'
                    if isinstance(exc, subprocess.CalledProcessError) else f'Error: {exc}\n')

if __name__ == '__main__': main()
