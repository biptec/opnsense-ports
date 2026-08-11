--- salt/minion.py.orig	2026-06-11 12:00:21.000000000 +0000
+++ salt/minion.py	2026-08-11 13:16:02.778395000 +0000
@@ -162,6 +162,10 @@
 # 6. Handle publications


+class _SourceInterfaceUnavailable(SystemExit):
+    """Abort startup when the configured source interface is unusable."""
+
+
 def resolve_dns(opts, fallback=True):
     """
     Resolves the master_ip and master_uri options
@@ -243,25 +247,27 @@
         interfaces = salt.utils.network.interfaces()
         log.trace("The following interfaces are available on this Minion:")
         log.trace(interfaces)
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
+        source_interface = opts["source_interface_name"]
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
     elif opts["source_address"]:
         ret["source_ip"] = salt.utils.network.dns_check(
             opts["source_address"], int(opts["source_ret_port"]), True, opts["ipv6"]
@@ -1341,6 +1347,11 @@
                     await minion.connect_master(failed=failed)
                 minion.tune_in(start=False)
                 self.minions.append(minion)
+                break
+            except _SourceInterfaceUnavailable as exc:
+                minion.destroy()
+                self._source_interface_exit_code = exc.code
+                self.io_loop.stop()
                 break
             except SaltClientError as exc:
                 minion.destroy()
@@ -1396,7 +1407,23 @@
         except (KeyboardInterrupt, SystemExit):
             pass
         finally:
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
             self.io_loop.close()
+        if source_interface_exit_code is not None:
+            raise SystemExit(source_interface_exit_code)

     @property
     def restart(self):
