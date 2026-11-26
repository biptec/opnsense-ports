#!/usr/bin/env python3
"""CARP ownership regressions for FreeBSD Zebra startup and live RTM handling.

Run as root only inside an otherwise empty disposable FreeBSD VNET jail.
The kernel under test must implement the #232 CARP route-ownership contract:
CARP BACKUP/INIT addresses remain configured but do not own direct-prefix or
local/self routes; MASTER addresses do. Ordinary non-CARP addresses remain
independent owners.

The parent harness pre-provisions exactly one Ethernet interface in the jail
and keeps its external epair peer UP for carrier. Each invocation runs one
scenario in a fresh jail.

An unpatched FRR 10.6.1 is expected to fail the startup-BACKUP scenarios because
NET_RT_IFLIST enumerates configured CARP addresses even when the native FIB does
not grant them ownership. The candidate must also preserve live PF_ROUTE
RTM_NEWADDR/RTM_DELADDR behavior without a CARP poller or devd consumer in
Zebra.
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
    parser.add_argument(
        "--zebra",
        default="/usr/local/sbin/zebra",
        help="Zebra executable to test, including an uninstalled build",
    )
    parser.add_argument(
        "--device",
        required=True,
        help="Pre-provisioned Ethernet interface inside this VNET; its external epair peer must be UP",
    )
    parser.add_argument(
        "--scenario",
        choices=("basic", "startup-master", "mixed", "multi-vhid"),
        default="basic",
        help="Ownership scenario to execute; run each scenario in a fresh VNET jail",
    )
    args = parser.parse_args()

    if os.geteuid() != 0 or run("sysctl", "-n", "security.jail.jailed").stdout.strip() != "1":
        raise RuntimeError("Requires root in a disposable empty VNET jail")

    interfaces = set(run("ifconfig", "-l").stdout.split())
    allowed = {"lo0", "enc0", "pflog0", "pfsync0", args.device}
    if args.device not in interfaces or interfaces - allowed:
        raise RuntimeError(
            f"Requires exactly one pre-provisioned test interface {args.device!r}; "
            f"found {sorted(interfaces)}"
        )

    work = Path(
        tempfile.mkdtemp(prefix=f"frr-carp-{args.scenario}-", dir="/tmp")
    )
    frr = pwd.getpwnam("frr")
    os.chown(work, frr.pw_uid, frr.pw_gid)
    config = work / "zebra.conf"
    config.write_text(
        f"hostname carp-{args.scenario}-test\nlog file {work}/zebra.log\n"
    )

    device = args.device
    pid = None
    vty = "/usr/local/bin/vtysh"

    def vty_routes(prefix: str, family: str) -> list:
        command = "show ip route" if family == "inet" else "show ipv6 route"
        output = run(
            vty,
            "--vty_socket",
            str(work),
            "-d",
            "zebra",
            "-c",
            f"{command} {prefix} json",
        ).stdout
        data = json.loads(output)
        return data.get(prefix, [])

    def protocols(prefix: str, family: str) -> set:
        return {route.get("protocol") for route in vty_routes(prefix, family)}

    def wait_protocol(
        prefix: str,
        family: str,
        protocol: str,
        present: bool,
        label: str,
    ) -> None:
        deadline = time.monotonic() + 5
        last = set()
        stable_since = None
        while time.monotonic() < deadline:
            last = protocols(prefix, family)
            matched = (protocol in last) == present
            if matched:
                if stable_since is None:
                    stable_since = time.monotonic()
                if time.monotonic() - stable_since >= 0.3:
                    print(
                        json.dumps(
                            {
                                "scenario": args.scenario,
                                "stage": label,
                                "prefix": prefix,
                                "protocol": protocol,
                                "present": present,
                                "observed": sorted(x for x in last if x),
                            }
                        ),
                        flush=True,
                    )
                    return
            else:
                stable_since = None
            time.sleep(0.1)
        raise AssertionError(
            f"{label}: protocol {protocol!r} present={present} "
            f"for {prefix}, observed={last}"
        )

    def assert_protocols(entries: list[tuple[str, str, str]], present: bool, label: str) -> None:
        for prefix, family, protocol in entries:
            wait_protocol(prefix, family, protocol, present, label)

    def carp_state(vhid: str, expected: str) -> None:
        deadline = time.monotonic() + 5
        last = ""
        while time.monotonic() < deadline:
            last = run("ifconfig", device).stdout
            if f"{expected} vhid {vhid}" in last:
                return
            time.sleep(0.1)
        raise AssertionError(f"CARP VHID {vhid} did not reach {expected}:\n{last}")

    def set_carp_state(vhid: str, state: str) -> None:
        run("ifconfig", device, "vhid", vhid, "state", state.lower())
        carp_state(vhid, state.upper())

    def fib_prefix_present(prefix: str, family: str) -> bool:
        target = ipaddress.ip_network(prefix)
        interface_column = None
        for line in run("netstat", "-rnW", "-f", family).stdout.splitlines():
            fields = line.split()
            if fields and fields[0] == "Destination" and "Netif" in fields:
                interface_column = fields.index("Netif")
                continue
            if interface_column is None or len(fields) <= interface_column:
                continue
            try:
                destination = ipaddress.ip_network(fields[0], strict=False)
            except ValueError:
                continue
            if destination == target and fields[interface_column] == device:
                return True
        return False

    def wait_native_prefix(
        prefix: str,
        family: str,
        present: bool,
        label: str,
    ) -> None:
        deadline = time.monotonic() + 5
        last = None
        stable_since = None
        while time.monotonic() < deadline:
            last = fib_prefix_present(prefix, family)
            if last == present:
                if stable_since is None:
                    stable_since = time.monotonic()
                if time.monotonic() - stable_since >= 0.2:
                    print(
                        json.dumps(
                            {
                                "scenario": args.scenario,
                                "stage": label,
                                "native_prefix": prefix,
                                "family": family,
                                "present": present,
                            }
                        ),
                        flush=True,
                    )
                    return
            else:
                stable_since = None
            time.sleep(0.1)
        raise AssertionError(
            f"{label}: native prefix {prefix} present={present}, observed={last}"
        )

    def start_zebra() -> int:
        with (work / "startup.log").open("w") as startup:
            subprocess.run(
                [
                    args.zebra,
                    "-d",
                    "-P",
                    "0",
                    "-f",
                    str(config),
                    "-i",
                    str(work / "zebra.pid"),
                    "-z",
                    str(work / "zserv.api"),
                    "--vty_socket",
                    str(work),
                ],
                stdout=startup,
                stderr=subprocess.STDOUT,
                check=True,
            )

        deadline = time.monotonic() + 5
        while not (work / "zebra.pid").exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        if not (work / "zebra.pid").exists():
            raise AssertionError("Zebra did not create its pid file")
        return int((work / "zebra.pid").read_text())

    def configure_carp(
        vhid: str,
        v4_addr: str,
        v6_addr: str,
        *,
        alias: bool = False,
        state: str,
    ) -> None:
        v4_args = [
            "ifconfig",
            device,
            "vhid",
            vhid,
            "advbase",
            "255",
            "advskew",
            "100",
            f"{v4_addr}/24",
        ]
        if alias:
            v4_args.append("alias")
        run(*v4_args)
        run(
            "ifconfig",
            device,
            "inet6",
            "add",
            "vhid",
            vhid,
            f"{v6_addr}/64",
        )
        set_carp_state(vhid, state)

    def scenario_basic() -> int:
        v4_addr = "192.0.2.250"
        v4_prefix = "192.0.2.0/24"
        v4_local = f"{v4_addr}/32"
        v6_addr = "2001:db8:232::250"
        v6_prefix = "2001:db8:232::/64"
        v6_local = f"{v6_addr}/128"
        vhid = "250"
        routes = [
            (v4_prefix, "inet", "connected"),
            (v4_local, "inet", "local"),
            (v6_prefix, "inet6", "connected"),
            (v6_local, "inet6", "local"),
        ]

        configure_carp(vhid, v4_addr, v6_addr, state="BACKUP")
        wait_native_prefix(v4_prefix, "inet", False, "native BACKUP before Zebra")
        wait_native_prefix(v6_prefix, "inet6", False, "native BACKUP before Zebra")

        zebra_pid = start_zebra()
        assert_protocols(routes, False, "fresh Zebra while BACKUP")

        set_carp_state(vhid, "MASTER")
        wait_native_prefix(v4_prefix, "inet", True, "native MASTER")
        wait_native_prefix(v6_prefix, "inet6", True, "native MASTER")
        assert_protocols(routes, True, "live BACKUP->MASTER")
        assert_protocols(
            [
                (v4_local, "inet", "kernel"),
                (v6_local, "inet6", "kernel"),
            ],
            False,
            "local address routes are not duplicated as kernel routes",
        )

        set_carp_state(vhid, "BACKUP")
        wait_native_prefix(v4_prefix, "inet", False, "native BACKUP after MASTER")
        wait_native_prefix(v6_prefix, "inet6", False, "native BACKUP after MASTER")
        assert_protocols(routes, False, "live MASTER->BACKUP")
        assert_protocols(
            [
                (v4_local, "inet", "kernel"),
                (v6_local, "inet6", "kernel"),
            ],
            False,
            "BACKUP has no stale kernel local-address route",
        )
        return zebra_pid

    def scenario_startup_master() -> int:
        v4_addr = "192.0.2.249"
        v4_prefix = "192.0.2.0/24"
        v4_local = f"{v4_addr}/32"
        v6_addr = "2001:db8:233::249"
        v6_prefix = "2001:db8:233::/64"
        v6_local = f"{v6_addr}/128"
        vhid = "249"
        routes = [
            (v4_prefix, "inet", "connected"),
            (v4_local, "inet", "local"),
            (v6_prefix, "inet6", "connected"),
            (v6_local, "inet6", "local"),
        ]

        configure_carp(vhid, v4_addr, v6_addr, state="MASTER")
        wait_native_prefix(v4_prefix, "inet", True, "native MASTER before Zebra")
        wait_native_prefix(v6_prefix, "inet6", True, "native MASTER before Zebra")

        zebra_pid = start_zebra()
        assert_protocols(routes, True, "fresh Zebra while MASTER")
        assert_protocols(
            [
                (v4_local, "inet", "kernel"),
                (v6_local, "inet6", "kernel"),
            ],
            False,
            "startup MASTER local routes are not duplicated as kernel routes",
        )

        set_carp_state(vhid, "BACKUP")
        wait_native_prefix(v4_prefix, "inet", False, "native BACKUP")
        wait_native_prefix(v6_prefix, "inet6", False, "native BACKUP")
        assert_protocols(routes, False, "live MASTER->BACKUP")

        set_carp_state(vhid, "MASTER")
        wait_native_prefix(v4_prefix, "inet", True, "native MASTER after BACKUP")
        wait_native_prefix(v6_prefix, "inet6", True, "native MASTER after BACKUP")
        assert_protocols(routes, True, "live BACKUP->MASTER")
        return zebra_pid

    def scenario_mixed() -> int:
        v4_prefix = "198.51.100.0/24"
        ordinary_v4 = "198.51.100.2"
        carp_v4 = "198.51.100.1"
        v6_prefix = "2001:db8:30::/64"
        ordinary_v6 = "2001:db8:30::2"
        carp_v6 = "2001:db8:30::1"
        vhid = "248"

        run("ifconfig", device, f"{ordinary_v4}/24", "up")
        run("ifconfig", device, "inet6", f"{ordinary_v6}/64", "no_dad")
        configure_carp(vhid, carp_v4, carp_v6, alias=True, state="BACKUP")

        wait_native_prefix(v4_prefix, "inet", True, "ordinary owner keeps v4 prefix")
        wait_native_prefix(v6_prefix, "inet6", True, "ordinary owner keeps v6 prefix")

        zebra_pid = start_zebra()

        assert_protocols(
            [
                (v4_prefix, "inet", "connected"),
                (f"{ordinary_v4}/32", "inet", "local"),
                (v6_prefix, "inet6", "connected"),
                (f"{ordinary_v6}/128", "inet6", "local"),
            ],
            True,
            "fresh Zebra ordinary owner + CARP BACKUP",
        )
        assert_protocols(
            [
                (f"{carp_v4}/32", "inet", "local"),
                (f"{carp_v6}/128", "inet6", "local"),
            ],
            False,
            "fresh Zebra suppresses CARP BACKUP locals",
        )

        set_carp_state(vhid, "MASTER")
        wait_native_prefix(v4_prefix, "inet", True, "mixed CARP MASTER v4 prefix")
        wait_native_prefix(v6_prefix, "inet6", True, "mixed CARP MASTER v6 prefix")
        assert_protocols(
            [
                (v4_prefix, "inet", "connected"),
                (v6_prefix, "inet6", "connected"),
                (f"{ordinary_v4}/32", "inet", "local"),
                (f"{ordinary_v6}/128", "inet6", "local"),
                (f"{carp_v4}/32", "inet", "local"),
                (f"{carp_v6}/128", "inet6", "local"),
            ],
            True,
            "mixed BACKUP->MASTER",
        )

        set_carp_state(vhid, "BACKUP")
        wait_native_prefix(v4_prefix, "inet", True, "ordinary owner survives v4 CARP withdrawal")
        wait_native_prefix(v6_prefix, "inet6", True, "ordinary owner survives v6 CARP withdrawal")
        assert_protocols(
            [
                (v4_prefix, "inet", "connected"),
                (v6_prefix, "inet6", "connected"),
                (f"{ordinary_v4}/32", "inet", "local"),
                (f"{ordinary_v6}/128", "inet6", "local"),
            ],
            True,
            "mixed MASTER->BACKUP keeps ordinary ownership",
        )
        assert_protocols(
            [
                (f"{carp_v4}/32", "inet", "local"),
                (f"{carp_v6}/128", "inet6", "local"),
            ],
            False,
            "mixed MASTER->BACKUP withdraws CARP locals",
        )
        return zebra_pid

    def scenario_multi_vhid() -> int:
        v4_prefix = "203.0.113.0/24"
        v6_prefix = "2001:db8:40::/64"
        master_vhid = "247"
        backup_vhid = "246"
        master_v4 = "203.0.113.247"
        backup_v4 = "203.0.113.246"
        master_v6 = "2001:db8:40::247"
        backup_v6 = "2001:db8:40::246"

        configure_carp(master_vhid, master_v4, master_v6, state="MASTER")
        configure_carp(
            backup_vhid,
            backup_v4,
            backup_v6,
            alias=True,
            state="BACKUP",
        )
        # Reassert the intended split after the second VHID is created.
        set_carp_state(master_vhid, "MASTER")
        set_carp_state(backup_vhid, "BACKUP")

        wait_native_prefix(v4_prefix, "inet", True, "one MASTER owns shared v4 prefix")
        wait_native_prefix(v6_prefix, "inet6", True, "one MASTER owns shared v6 prefix")

        zebra_pid = start_zebra()

        assert_protocols(
            [
                (v4_prefix, "inet", "connected"),
                (v6_prefix, "inet6", "connected"),
                (f"{master_v4}/32", "inet", "local"),
                (f"{master_v6}/128", "inet6", "local"),
            ],
            True,
            "fresh Zebra split VHID ownership",
        )
        assert_protocols(
            [
                (f"{backup_v4}/32", "inet", "local"),
                (f"{backup_v6}/128", "inet6", "local"),
            ],
            False,
            "fresh Zebra suppresses BACKUP VHID locals",
        )

        # Promote the standby first so the shared prefix never has zero local
        # owners, then demote the previous owner.
        set_carp_state(backup_vhid, "MASTER")
        wait_native_prefix(v4_prefix, "inet", True, "two MASTERs keep v4 prefix")
        wait_native_prefix(v6_prefix, "inet6", True, "two MASTERs keep v6 prefix")
        assert_protocols(
            [
                (f"{backup_v4}/32", "inet", "local"),
                (f"{backup_v6}/128", "inet6", "local"),
            ],
            True,
            "second VHID BACKUP->MASTER adds locals",
        )

        set_carp_state(master_vhid, "BACKUP")
        wait_native_prefix(v4_prefix, "inet", True, "new MASTER keeps shared v4 prefix")
        wait_native_prefix(v6_prefix, "inet6", True, "new MASTER keeps shared v6 prefix")
        assert_protocols(
            [
                (v4_prefix, "inet", "connected"),
                (v6_prefix, "inet6", "connected"),
                (f"{backup_v4}/32", "inet", "local"),
                (f"{backup_v6}/128", "inet6", "local"),
            ],
            True,
            "shared prefix survives VHID handoff",
        )
        assert_protocols(
            [
                (f"{master_v4}/32", "inet", "local"),
                (f"{master_v6}/128", "inet6", "local"),
            ],
            False,
            "old MASTER locals withdrawn",
        )

        # Reverse once to prove the bookkeeping is not order-specific.
        set_carp_state(master_vhid, "MASTER")
        assert_protocols(
            [
                (f"{master_v4}/32", "inet", "local"),
                (f"{master_v6}/128", "inet6", "local"),
            ],
            True,
            "old VHID promoted again",
        )
        set_carp_state(backup_vhid, "BACKUP")
        assert_protocols(
            [
                (v4_prefix, "inet", "connected"),
                (v6_prefix, "inet6", "connected"),
                (f"{master_v4}/32", "inet", "local"),
                (f"{master_v6}/128", "inet6", "local"),
            ],
            True,
            "reverse shared-prefix handoff",
        )
        assert_protocols(
            [
                (f"{backup_v4}/32", "inet", "local"),
                (f"{backup_v6}/128", "inet6", "local"),
            ],
            False,
            "reverse handoff withdraws old locals",
        )
        return zebra_pid

    try:
        run("ifconfig", device, "up")
        run("sysctl", "net.inet.carp.preempt=1")

        scenarios = {
            "basic": scenario_basic,
            "startup-master": scenario_startup_master,
            "mixed": scenario_mixed,
            "multi-vhid": scenario_multi_vhid,
        }
        pid = scenarios[args.scenario]()
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "test": "carp-startup-ownership",
                    "scenario": args.scenario,
                }
            ),
            flush=True,
        )
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
        print(f"Test evidence directory: {work}", flush=True)


if __name__ == "__main__":
    main()
