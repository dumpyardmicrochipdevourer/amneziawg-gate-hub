#!/usr/bin/env python3
"""Sync `ip rule` priority 10005 (client address -> hub table) with cascade-bindings.list."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from collections.abc import Collection

__all__ = [
    'PRIORITY', 'LOCK_TIMEOUT', 'ip', 'RulesStateError', 'RulesApplyError',
    'parse_bindings', 'parse_rules', 'sync', 'main',
]

PRIORITY = 10005
LOCK_TIMEOUT = 30.0
_LOCK_RETRY = 0.1
_DEFAULT_DIR = '/etc/amnezia/amneziawg'
_UNREACHABLE_METRIC = '32760'

_IFACE = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,14}')
_BINDING_LINE = re.compile(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3}) ([0-9]{1,10})')
_RULE_LINE = re.compile(r'(\d+):\s+(.*)')
_RULE_BODY = re.compile(r'from (\S+) iif (\S+)(?: \[detached\])? lookup (\S+)')
_BARE_ADDRESS = re.compile(r'\d+\.\d+\.\d+\.\d+')


class RulesStateError(Exception):
    """Settings or bindings are missing, unreadable or corrupted (exit code 3)."""


class RulesApplyError(Exception):
    """`ip` failed, unparsable rule on our priority, or lock timeout (exit code 4)."""


def ip(*args):
    return subprocess.run(['ip', *args], text=True, capture_output=True, check=True).stdout


def _run_ip(*args):
    try:
        return ip(*args)
    except subprocess.CalledProcessError as exc:
        raise RulesApplyError(f'ip {" ".join(args)} failed with code {exc.returncode}') from exc
    except OSError as exc:
        raise RulesApplyError(f'cannot run ip: {type(exc).__name__}') from exc


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _read_text(path, what):
    try:
        return path.read_bytes().decode('utf-8')
    except OSError as exc:
        raise RulesStateError(f'cannot read {what} {path}: {type(exc).__name__}') from exc
    except UnicodeDecodeError as exc:
        raise RulesStateError(f'{what} {path} is not valid UTF-8') from exc


def parse_bindings(text: str, network: ipaddress.IPv4Network, tables: Collection[int]) -> dict[str, int]:
    result: dict[str, int] = {}
    for number, line in enumerate(text.split('\n'), 1):
        if line == '' or line.startswith('#'):
            continue
        match = _BINDING_LINE.fullmatch(line)
        if match is None:
            raise RulesStateError(f'bindings line {number}: invalid format')
        address, table = match[1], int(match[2])
        try:
            parsed = ipaddress.IPv4Address(address)
        except ValueError as exc:
            raise RulesStateError(f'bindings line {number}: invalid address {address}') from exc
        if str(parsed) != address or parsed not in network or not 2 <= int(parsed) & 0xFF <= 254:
            raise RulesStateError(f'bindings line {number}: address {address} not allowed')
        if table not in tables:
            raise RulesStateError(f'bindings line {number}: unknown table {table}')
        if address in result:
            raise RulesStateError(f'bindings line {number}: duplicate address {address}')
        result[address] = table
    return result


def parse_rules(output: str) -> list[tuple[str, str, str]]:
    rules = []
    for line in output.split('\n'):
        match = _RULE_LINE.fullmatch(line)
        if match is None or int(match[1]) != PRIORITY:
            continue
        body = _RULE_BODY.fullmatch(match[2].strip())
        if body is None:
            raise RulesApplyError(f'cannot parse rule at priority {PRIORITY}: {line.strip()}')
        src, iif, table = body.groups()
        if _BARE_ADDRESS.fullmatch(src):
            src += '/32'
        rules.append((src, iif, table))
    return rules


def _valid_client_network(value):
    if not isinstance(value, str):
        return None
    try:
        network = ipaddress.IPv4Network(value)
    except ValueError:
        return None
    return network if network.prefixlen == 24 and str(network) == value else None


def _check_hubs(hubs):
    if not isinstance(hubs, dict) or not hubs:
        raise RulesStateError('settings: hubs must be a non-empty object')
    for name, hub in hubs.items():
        if not isinstance(hub, dict) or not _is_int(hub.get('table')):
            raise RulesStateError(f'settings: hub {name} has no integer table')


def _load_settings(base):
    text = _read_text(base / 'cascade-settings.json', 'settings')
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise RulesStateError('settings are not valid JSON') from exc
    if not isinstance(data, dict) or 'hubs' not in data:
        raise RulesStateError('settings have the old format; run gate.yml')
    interface = data.get('interface')
    if not isinstance(interface, str) or _IFACE.fullmatch(interface) is None:
        raise RulesStateError('settings: invalid interface')
    _check_hubs(data['hubs'])
    default_hub = data.get('default_hub')
    if not isinstance(default_hub, str) or default_hub not in data['hubs']:
        raise RulesStateError('settings: default_hub is not one of hubs')
    network = _valid_client_network(data.get('client_network'))
    if network is None:
        raise RulesStateError('settings: invalid client_network')
    tables = {hub['table'] for hub in data['hubs'].values()}
    stub = data.get('stub_table')
    if not _is_int(stub) or stub in tables:
        raise RulesStateError('settings: invalid stub_table')
    return interface, network, tables, stub


def _acquire_lock(base):
    try:
        handle = (base / '.cascade-rules.lock').open('ab')
    except FileNotFoundError as exc:
        raise RulesStateError(f'config directory {base} does not exist') from exc
    except OSError as exc:
        raise RulesApplyError(f'cannot open lock file: {type(exc).__name__}') from exc
    deadline = time.monotonic() + LOCK_TIMEOUT
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle
        except OSError:
            if time.monotonic() >= deadline:
                handle.close()
                raise RulesApplyError('timed out waiting for .cascade-rules.lock') from None  # reason is the timeout itself
            time.sleep(_LOCK_RETRY)


def _address_key(entry):
    return int(ipaddress.IPv4Address(entry[0].split('/')[0]))


def _plan(desired, current):
    """Return (to_add sorted by address, to_delete in `show` order)."""
    unmatched = set(desired)
    to_delete = []
    for entry in current:
        if entry in unmatched:
            unmatched.discard(entry)
        else:
            to_delete.append(entry)
    return sorted(set(desired) - set(current), key=_address_key), to_delete


def _ensure_unreachable(stub, tables):
    for table in [stub, *sorted(tables)]:
        _run_ip('-4', 'route', 'replace', 'unreachable', 'default', 'metric', _UNREACHABLE_METRIC,
                'table', str(table))


def _apply(to_add, to_delete):
    for src, iif, table in to_add:
        _run_ip('-4', 'rule', 'add', 'from', src, 'iif', iif, 'priority', str(PRIORITY), 'lookup', table)
    for src, iif, table in to_delete:
        _run_ip('-4', 'rule', 'del', 'from', src, 'iif', iif, 'priority', str(PRIORITY), 'lookup', table)


def _sync_locked(base):
    interface, network, tables, stub = _load_settings(base)
    text = _read_text(base / 'cascade-bindings.list', 'bindings')
    bindings = parse_bindings(text, network, tables)
    desired = {(f'{address}/32', interface, str(table)) for address, table in bindings.items()}
    _ensure_unreachable(stub, tables)
    current = parse_rules(_run_ip('-4', '-N', 'rule', 'show'))
    to_add, to_delete = _plan(desired, current)
    _apply(to_add, to_delete)
    return len(to_add), len(to_delete)


def sync(base: Path, lock: bool = True) -> tuple[int, int]:
    base = Path(base)
    handle = _acquire_lock(base) if lock else None
    try:
        return _sync_locked(base)
    finally:
        if handle is not None:
            handle.close()  # closing releases the flock


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='awg-cascade-rules', description=__doc__)
    parser.add_argument('--config-dir', default=None)
    parser.add_argument('--no-lock', action='store_true', help='caller already holds .cascade-rules.lock')
    args = parser.parse_args(argv)
    base = Path(args.config_dir or os.environ.get('AWG_CONFIG_DIR') or _DEFAULT_DIR)
    try:
        added, removed = sync(base, lock=not args.no_lock)
    except (RulesStateError, RulesApplyError) as exc:
        sys.stderr.write(f'Error: {" ".join(str(exc).split())}\n')
        return 3 if isinstance(exc, RulesStateError) else 4
    sys.stdout.write(f'added={added} removed={removed}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
