# Native BSD route-notification regression

Run `test_kernel_route_notifications.py` as root **only inside an otherwise empty, disposable FreeBSD VNET jail** with FRR and Python 3 installed. The script rejects non-jail execution and an existing data interface. It creates its own bridge interfaces, test routes, private Zebra socket/configuration and evidence directory; its cleanup stops only its Zebra instance and removes its own interfaces/routes. It does not need OSPF, CARP, a network connection or a prefix policy.

```
python3 test_kernel_route_notifications.py --suite single
python3 test_kernel_route_notifications.py --suite linklocal
```

`single` covers IPv4/IPv6 host and subnet routes: ADD, repeated GET, alternating and identical next-hop CHANGE, DELETE and re-ADD. `linklocal` changes an IPv6 route between the same link-local address on two different interfaces, checking that the scope/interface is retained. Both compare the complete gateway/interface path in Zebra with the actual FreeBSD FIB and require a stable match; counting routes alone is insufficient.

The expected invariant is one current kernel route after each single-path change, no historical K entries, and no K entry after deletion. Evidence is retained in the printed temporary directory. An unpatched FRR 10.6.1 fails the first single-path CHANGE by retaining the old K entry. It also loses the explicit `sin6_scope_id` on a link-local ADD notification, resolving the route through an unrelated interface.

## Independent multipath control

```
python3 test_kernel_route_notifications.py --suite multipath
```

This additional diagnostic is deliberately not converted into an expected-pass or suppressed assertion. On FreeBSD 15.1 with the tested native route(8), `route change PREFIX GATEWAY -weight 2` replaces the entire multipath group with a single next-hop; it does not merely update one member's weight. The test verifies the FIB before comparing Zebra.

FRR 10.6.1 and the RTM_CHANGE-only 10.6.1_2 package fail `two next-hops -> one -> re-add the other`: FIB contains two different next-hops while Zebra contains two copies of the survivor. A native PF_ROUTE capture records ADD(A), DELETE(B), ADD(B); the kernel supplies the correct gateway for every event. In `rib_process_sys_route()`, passing NULL instead of the context nexthop to `rib_delete()` removes A instead of B, after which B is duplicated. The path-specific DELETE fix preserves this nexthop and its interface scope. It also retains `rtm_index` and uses the interface-qualified nexthop type for IPv4 and global IPv6, not only link-local addresses. Otherwise the RIB has an IPV4_IFINDEX path while DELETE supplies IPV4/ifindex=0, and exact matching leaves the route behind. The native diagnostic measured this mismatch (type 3/index 10 versus type 2/index 0); the corrected build passes all 68 single-path, 17 link-local and 22 multipath assertions without relaxing the tests. All three suites must pass on the packaged binary before release.

An uninstalled native build can be tested with `--zebra /absolute/path/to/zebra/zebra`; the default remains the installed `/usr/local/sbin/zebra`. All jail isolation guards and FIB/RIB assertions still apply. Merely compiling the patch or clearing the existing RIB does not count as a regression-test PASS.

These isolated tests do not replace HA acceptance. Repeated real CARP transitions, interface-sensitive OSPF export, fresh-primary forwarding before reverse sync, established flows and deployment idempotency must still be checked on the packaged implementation.
