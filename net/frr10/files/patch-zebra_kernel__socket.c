--- zebra/kernel_socket.c.orig
+++ zebra/kernel_socket.c
@@ -1005,7 +1005,8 @@
 	short ifnlen = 0;
 	struct nexthop nh;
 	struct prefix p;
-	ifindex_t ifindex = 0;
+	/* Keep the kernel path identity for both ADD and DELETE. */
+	ifindex_t ifindex = rtm->rtm_index;
 	afi_t afi;
 	char fbuf[64];
 	int32_t proto = ZEBRA_ROUTE_KERNEL;
@@ -1109,7 +1110,12 @@
 	/* Handle IPv6 link-local gateway addresses */
 	if (afi == AFI_IP6 && has_gateway && gate.sa.sa_family == AF_INET6) {
 		if (IN6_IS_ADDR_LINKLOCAL(&gate.sin6.sin6_addr)) {
-			ifindex = IN6_LINKLOCAL_IFINDEX(gate.sin6.sin6_addr);
+			/* FreeBSD reports the link-local zone separately on routing
+			 * socket notifications. Retain embedded zones for older BSDs. */
+			if (gate.sin6.sin6_scope_id)
+				ifindex = gate.sin6.sin6_scope_id;
+			else if (IN6_LINKLOCAL_IFINDEX(gate.sin6.sin6_addr))
+				ifindex = IN6_LINKLOCAL_IFINDEX(gate.sin6.sin6_addr);
 			SET_IN6_LINKLOCAL_IFINDEX(gate.sin6.sin6_addr, 0);
 		}
 	}
@@ -1124,8 +1130,10 @@
 	} else if (flags & RTF_GATEWAY) {
 		/* Traditional gateway route */
 		if (afi == AFI_IP) {
-			nh.type = NEXTHOP_TYPE_IPV4;
+			nh.type = ifindex ? NEXTHOP_TYPE_IPV4_IFINDEX
+					  : NEXTHOP_TYPE_IPV4;
 			nh.gate.ipv4 = gate.sin.sin_addr;
+			nh.ifindex = ifindex;
 		} else if (afi == AFI_IP6) {
 			nh.type = ifindex ? NEXTHOP_TYPE_IPV6_IFINDEX
 					  : NEXTHOP_TYPE_IPV6;
@@ -1161,6 +1169,10 @@
 
 	/* Initialize context with basic route info */
 	dplane_ctx_route_init_basic(ctx, op, NULL, NULL, NULL, afi, SAFI_UNICAST);
+
+	/* A kernel route change replaces the previous RIB entry. Basic init
+	 * leaves replace unset when no route_entry is supplied above. */
+	dplane_ctx_route_set_replace(ctx, rtm->rtm_type == RTM_CHANGE);
 
 	/* Set destination prefix explicitly */
 	dplane_ctx_set_dest(ctx, &p);
