--- zebra/kernel_socket.c.orig
+++ zebra/kernel_socket.c
@@ -1109,7 +1109,11 @@
 	/* Handle IPv6 link-local gateway addresses */
 	if (afi == AFI_IP6 && has_gateway && gate.sa.sa_family == AF_INET6) {
 		if (IN6_IS_ADDR_LINKLOCAL(&gate.sin6.sin6_addr)) {
-			ifindex = IN6_LINKLOCAL_IFINDEX(gate.sin6.sin6_addr);
+			/* FreeBSD reports the link-local zone separately on routing
+			 * socket notifications. Retain embedded zones for older BSDs. */
+			ifindex = gate.sin6.sin6_scope_id;
+			if (!ifindex)
+				ifindex = IN6_LINKLOCAL_IFINDEX(gate.sin6.sin6_addr);
 			SET_IN6_LINKLOCAL_IFINDEX(gate.sin6.sin6_addr, 0);
 		}
 	}
@@ -1161,6 +1165,10 @@
 
 	/* Initialize context with basic route info */
 	dplane_ctx_route_init_basic(ctx, op, NULL, NULL, NULL, afi, SAFI_UNICAST);
+
+	/* A kernel route change replaces the previous RIB entry. Basic init
+	 * leaves replace unset when no route_entry is supplied above. */
+	dplane_ctx_route_set_replace(ctx, rtm->rtm_type == RTM_CHANGE);
 
 	/* Set destination prefix explicitly */
 	dplane_ctx_set_dest(ctx, &p);
