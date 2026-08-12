--- salt/minion.py.orig
+++ salt/minion.py
@@ -164,0 +165,4 @@
+class _SourceInterfaceUnavailable(SystemExit):
+    """Abort startup when the configured source interface is unusable."""
+
+
@@ -177 +181,44 @@
-    if check_dns is True:
+    source_interface = opts["source_interface_name"]
+    if check_dns and source_interface:
+        # source_interface_name is a security boundary on managed network nodes.
+        # Validate it before any master DNS lookup or connectivity probe: upstream
+        # dns_check() opens an unbound test socket before source_ip is applied.
+        log.trace("Custom source interface required: %s", source_interface)
+        interfaces = salt.utils.network.interfaces()
+        log.trace("The following interfaces are available on this Minion:")
+        log.trace(interfaces)
+        if source_interface not in interfaces:
+            err = f"Configured source interface {source_interface} is not available"
+            log.error(err)
+            raise _SourceInterfaceUnavailable(42)
+        if not interfaces[source_interface]["up"]:
+            err = f"Configured source interface {source_interface} is down"
+            log.error(err)
+            raise _SourceInterfaceUnavailable(42)
+        addrs = (
+            interfaces[source_interface]["inet"]
+            if not opts["ipv6"]
+            else interfaces[source_interface]["inet6"]
+        )
+        if not addrs:
+            family = "IPv6" if opts["ipv6"] else "IPv4"
+            err = f"Configured source interface {source_interface} has no {family} address"
+            log.error(err)
+            raise _SourceInterfaceUnavailable(42)
+        ret["source_ip"] = addrs[0]["address"]
+        log.debug("Using %s as source IP address", ret["source_ip"])
+
+        # A hostname would require an unbound system resolver query.  A literal
+        # master address keeps startup network-silent until Salt opens the real
+        # transport socket, which is then bound to source_ip above.
+        try:
+            master_address = ipaddress.ip_address(opts["master"])
+        except ValueError:
+            err = (
+                "Configured master must be a literal IP address when "
+                "source_interface_name is set"
+            )
+            log.error(err)
+            raise _SourceInterfaceUnavailable(42)
+        ret["master_ip"] = salt.utils.network.ip_bracket(str(master_address))
+    elif check_dns is True:
@@ -241,25 +288 @@
-    if opts["source_interface_name"]:
-        log.trace("Custom source interface required: %s", opts["source_interface_name"])
-        interfaces = salt.utils.network.interfaces()
-        log.trace("The following interfaces are available on this Minion:")
-        log.trace(interfaces)
-        if opts["source_interface_name"] in interfaces:
-            if interfaces[opts["source_interface_name"]]["up"]:
-                addrs = (
-                    interfaces[opts["source_interface_name"]]["inet"]
-                    if not opts["ipv6"]
-                    else interfaces[opts["source_interface_name"]]["inet6"]
-                )
-                ret["source_ip"] = addrs[0]["address"]
-                log.debug("Using %s as source IP address", ret["source_ip"])
-            else:
-                log.warning(
-                    "The interface %s is down so it cannot be used as source to connect"
-                    " to the Master",
-                    opts["source_interface_name"],
-                )
-        else:
-            log.warning(
-                "%s is not a valid interface. Ignoring.", opts["source_interface_name"]
-            )
-    elif opts["source_address"]:
+    if not source_interface and opts["source_address"]:
@@ -1344,0 +1368,5 @@
+            except _SourceInterfaceUnavailable as exc:
+                minion.destroy()
+                self._source_interface_exit_code = exc.code
+                self.io_loop.stop()
+                break
@@ -1398,0 +1427,14 @@
+            source_interface_exit_code = getattr(self, "_source_interface_exit_code", None)
+            if source_interface_exit_code is not None:
+                self.destroy()
+                pending_tasks = [
+                    task
+                    for task in asyncio.all_tasks(self.io_loop)
+                    if not task.done()
+                ]
+                for task in pending_tasks:
+                    task.cancel()
+                if pending_tasks:
+                    self.io_loop.run_until_complete(
+                        asyncio.gather(*pending_tasks, return_exceptions=True)
+                    )
@@ -1399,0 +1442,2 @@
+        if source_interface_exit_code is not None:
+            raise SystemExit(source_interface_exit_code)
