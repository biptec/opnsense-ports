#!/usr/bin/env python3
"""Native FRR routing-socket regression; run as root in an EMPTY VNET jail.

Requires the built frr10 package and Python. Never run in the router host's
network namespace. Each invocation starts an isolated Zebra instance, creates
its own bridge interfaces/routes, and removes them in finally. Nonzero exit is
a failure; the unpatched 10.6.1 daemon must fail the single-path CHANGE test.

    python3 test_kernel_route_notifications.py --suite single
    python3 test_kernel_route_notifications.py --suite multipath
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import tempfile
import time


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=10)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=('single', 'multipath', 'linklocal'), default='single')
    args = parser.parse_args()
    if os.geteuid() != 0 or run('sysctl', '-n', 'security.jail.jailed').stdout.strip() != '1':
        raise RuntimeError('Requires root in a disposable empty VNET jail')
    interfaces = set(run('ifconfig', '-l').stdout.split())
    # OPNsense creates these addressless pseudo-interfaces in every VNET.
    if interfaces - {'lo0', 'enc0', 'pflog0', 'pfsync0'}:
        raise RuntimeError(f'Refusing nonempty network namespace: {sorted(interfaces)}')

    work = Path(tempfile.mkdtemp(prefix='frr-rtsock-', dir='/tmp'))
    frr = pwd.getpwnam('frr')
    os.chown(work, frr.pw_uid, frr.pw_gid)
    config = work / 'zebra.conf'
    config.write_text(f'hostname rtsock-test\nlog file {work}/zebra.log\n')
    devices = []
    owned_routes = []
    results = []
    pid = None
    monitor = None
    vty = '/usr/local/bin/vtysh'

    def rib(prefix: str, family: str) -> list:
        command = 'show ip route' if family == 'inet' else 'show ipv6 route'
        data = json.loads(run(vty, '--vty_socket', str(work), '-d', 'zebra',
                              '-c', f'{command} {prefix} json').stdout)
        return [r for r in data.get(prefix, []) if r.get('protocol') == 'kernel']

    def fib_paths(prefix: str, family: str) -> set:
        target = ipaddress.ip_network(prefix)
        paths = set()
        interface_column = None
        for line in run('netstat', '-rnW', '-f', family).stdout.splitlines():
            fields = line.split()
            if fields and fields[0] == 'Destination' and 'Netif' in fields:
                interface_column = fields.index('Netif')
                continue
            if interface_column is None or len(fields) <= interface_column:
                continue
            try:
                destination = ipaddress.ip_network(fields[0], strict=False)
                gateway = str(ipaddress.ip_address(fields[1].split('%')[0]))
            except ValueError:
                continue
            if destination == target:
                paths.add((gateway, fields[interface_column]))
        return paths

    def check_routes(label: str, prefix: str, family: str, gateways: set) -> None:
        gateways = {str(ipaddress.ip_address(gateway.split('%')[0])) for gateway in gateways}
        expected_paths = fib_paths(prefix, family)
        if {gateway for gateway, _ in expected_paths} != gateways:
            raise AssertionError(f'{label}: test operation produced unexpected FIB: {expected_paths}')
        deadline = time.monotonic() + 5
        current = []
        stable_since = None
        while time.monotonic() < deadline:
            current = rib(prefix, family)
            observed_paths = {(str(ipaddress.ip_address(n['ip'].split('%')[0])),
                               n.get('interfaceName', ''))
                              for r in current for n in r.get('nexthops', []) if 'ip' in n}
            observed = {gateway for gateway, _ in observed_paths}
            if len(current) == len(gateways) and observed_paths == expected_paths:
                if stable_since is None:
                    stable_since = time.monotonic()
                if time.monotonic() - stable_since < 0.3:
                    time.sleep(0.1)
                    continue
                results.append({'stage': label, 'prefix': prefix,
                                'kernel_entries': len(current), 'gateways': sorted(observed)})
                print(json.dumps(results[-1]), flush=True)
                return
            stable_since = None
            time.sleep(0.1)
        (work / 'failure-fib.txt').write_text(run('netstat', '-rn').stdout)
        raise AssertionError(f'{label}: expected {len(gateways)} K routes matching FIB {expected_paths}; got {current}')

    def change(family: str, prefix: str, gateway: str, *extra: str) -> None:
        run('route', 'change', '-'+family, prefix, gateway, *extra)

    try:
        with (work / 'notifications.log').open('w') as notifications:
            monitor = subprocess.Popen(['route', '-n', 'monitor'],
                                       stdin=subprocess.DEVNULL, stdout=notifications,
                                       stderr=subprocess.STDOUT)
        for ipv4, ipv6 in [('192.0.2.1/24', '2001:db8:1::1/64'),
                           ('198.51.100.1/24', '2001:db8:2::1/64')]:
            device = run('ifconfig', 'bridge', 'create').stdout.strip()
            devices.append(device)
            run('ifconfig', device, 'inet', ipv4, 'up')
            run('ifconfig', device, 'inet6', ipv6)
            run('ifconfig', device, 'inet6', 'fe80::1/64')
        # A daemon may retain its startup descriptors; do not wait for pipe EOF.
        with (work/'startup.log').open('w') as startup:
            subprocess.run(['/usr/local/sbin/zebra', '-d', '-P', '0', '-f', str(config),
                            '-i', str(work/'zebra.pid'), '-z', str(work/'zserv.api'),
                            '--vty_socket', str(work)], stdout=startup,
                           stderr=subprocess.STDOUT, check=True)
        deadline = time.monotonic()+5
        while not (work/'zebra.pid').exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        pid = int((work/'zebra.pid').read_text())
        time.sleep(1)
        cases = [('inet', '203.0.113.250/32', '192.0.2.2', '198.51.100.2'),
                 ('inet6', '2001:db8:122::fffa/128', '2001:db8:1::2', '2001:db8:2::2')]
        if args.suite == 'single':
            cases.extend([
                ('inet', '203.0.113.0/25', '192.0.2.2', '198.51.100.2'),
                ('inet6', '2001:db8:122:1::/64', '2001:db8:1::2', '2001:db8:2::2'),
            ])
        elif args.suite == 'linklocal':
            cases = [('inet6', '2001:db8:122::fffb/128',
                      f'fe80::2%{devices[0]}', f'fe80::2%{devices[1]}')]
        for family, prefix, first, second in cases:
            run('route', 'add', '-'+family, prefix, first)
            owned_routes.append((family, prefix))
            check_routes('ADD', prefix, family, {first})
            for _ in range(3):
                run('route', '-n', 'get', '-'+family, prefix.split('/')[0])
            check_routes('GET does not duplicate', prefix, family, {first})
            if args.suite != 'multipath':
                for iteration in range(12):
                    gateway = second if iteration % 2 == 0 else first
                    change(family, prefix, gateway)
                    check_routes(f'CHANGE {iteration+1}', prefix, family, {gateway})
                    fib = run('route', '-n', 'get', '-'+family, prefix.split('/')[0]).stdout
                    fields = dict(line.strip().split(':', 1) for line in fib.splitlines() if ':' in line)
                    if fields.get('gateway', '').strip() != gateway:
                        raise AssertionError(f'FIB mismatch after CHANGE: {fib}')
                for _ in range(3):
                    change(family, prefix, first)
                check_routes('same-next-hop CHANGE', prefix, family, {first})
                run('route', 'delete', '-'+family, prefix)
                owned_routes.remove((family, prefix))
                check_routes('DELETE', prefix, family, set())
                run('route', 'add', '-'+family, prefix, second)
                owned_routes.append((family, prefix))
                check_routes('ADD after DELETE', prefix, family, {second})
            else:
                run('route', 'add', '-'+family, prefix, second)
                owned_routes.append((family, prefix))
                check_routes('multipath ADD preserves both', prefix, family, {first, second})
                # Native route(8) replaces the whole nexthop group here, not
                # only one member. Verify FIB first, then the matching Zebra RIB.
                for gateway in [second, first, second, first]:
                    change(family, prefix, gateway, '-weight', '2')
                    check_routes('multipath to single CHANGE', prefix, family, {gateway})
                    other = first if gateway == second else second
                    run('route', 'add', '-'+family, prefix, other)
                    check_routes('multipath ADD restores both', prefix, family, {first, second})
        print(json.dumps({'result': 'PASS', 'suite': args.suite, 'assertions': len(results)}))
    finally:
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            for _ in range(50):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
        for family, prefix in reversed(owned_routes):
            run('route', 'delete', '-'+family, prefix, check=False)
        for device in reversed(devices):
            run('ifconfig', device, 'destroy', check=False)
        if monitor is not None:
            monitor.terminate()
            monitor.wait(timeout=5)
        # Preserve Zebra's log on failure for diagnosis, but leave no daemon/routes.
        print(f'Test evidence directory: {work}', flush=True)


if __name__ == '__main__':
    main()
