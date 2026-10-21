--- zebra/zebra_rib.c.orig
+++ zebra/zebra_rib.c
@@ -4903,7 +4903,16 @@
 		rib_add_multipath(afi, SAFI_UNICAST, (struct prefix *)prefix, NULL, re, ng, false,
 				  dplane_ctx_route_get_replace(ctx));
 	} else if (op == DPLANE_OP_SYS_ROUTE_DELETE) {
-		rib_delete(afi, SAFI_UNICAST, vrf_id, proto, 0, flags, prefix, NULL, NULL, 0,
+		/* BSD notifications identify the path being deleted.  Dropping the
+		 * nexthop turns a path-specific delete into a prefix-only delete,
+		 * which can remove another path and retain a stale kernel route.
+		 * Use the same interface resolution as the add path above.
+		 */
+		nexthop = dplane_ctx_get_ng(ctx)->nexthop;
+		if (nexthop && nexthop->ifindex == IFINDEX_INTERNAL && ifindex > 0)
+			nexthop->ifindex = ifindex;
+
+		rib_delete(afi, SAFI_UNICAST, vrf_id, proto, 0, flags, prefix, NULL, nexthop, 0,
 			   table, 0, distance, false);
 	}
 }
