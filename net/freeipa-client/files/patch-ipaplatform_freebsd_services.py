--- /dev/null	2026-08-09 12:59:06.445036886 +0000
+++ ipaplatform/freebsd/services.py
@@ -0,0 +1,119 @@
+import os
+
+from ipaplatform.base import services as base_services
+from ipaplatform.paths import paths
+from ipapython import ipautil
+
+
+_SERVICE_NAMES = {
+    "sshd": "sshd",
+    "sssd": "sssd",
+    "unbound": "unbound",
+    "smb": "samba_server",
+    "winbind": "samba_server",
+    "chronyd": "chronyd",
+    "ntpd": "ntpd",
+    "autofs": "automountd",
+    "rpcgssd": "gssd",
+    "rpcidmapd": "nfsuserd",
+}
+
+
+class FreeBSDService(base_services.PlatformService):
+    def __init__(self, service_name, api=None):
+        super().__init__(service_name, api=api)
+        self.rc_name = _SERVICE_NAMES.get(service_name, service_name)
+
+    @property
+    def rc_script(self):
+        for root in ("/etc/rc.d", "/usr/local/etc/rc.d"):
+            candidate = os.path.join(root, self.rc_name)
+            if os.path.isfile(candidate):
+                return candidate
+        return None
+
+    def _service(self, action, capture_output=True):
+        if self.rc_script is None:
+            raise RuntimeError(f"FreeBSD service is not installed: {self.rc_name}")
+        return ipautil.run(
+            [paths.SBIN_SERVICE, self.rc_name, action],
+            capture_output=capture_output,
+        )
+
+    def start(self, instance_name="", capture_output=True, wait=True,
+              update_service_list=True):
+        self._service("start", capture_output)
+
+    def stop(self, instance_name="", capture_output=True,
+             update_service_list=True):
+        self._service("stop", capture_output)
+
+    def restart(self, instance_name="", capture_output=True, wait=True):
+        self._service("restart", capture_output)
+
+    def try_restart(self, instance_name="", capture_output=True, wait=True):
+        if self.is_running(instance_name):
+            self.restart(instance_name, capture_output, wait)
+
+    def is_running(self, instance_name="", wait=True):
+        if self.rc_script is None:
+            return False
+        try:
+            self._service("onestatus")
+            return True
+        except ipautil.CalledProcessError:
+            return False
+
+    def is_installed(self):
+        return self.rc_script is not None
+
+    def is_enabled(self, instance_name=""):
+        if self.rc_script is None:
+            return False
+        try:
+            result = ipautil.run(
+                ["/usr/sbin/sysrc", "-n", f"{self.rc_name}_enable"],
+                capture_output=True,
+            )
+        except ipautil.CalledProcessError:
+            return False
+        return result.output.strip().upper() in {"YES", "TRUE", "ON", "1"}
+
+    def enable(self, instance_name=""):
+        ipautil.run(["/usr/sbin/sysrc", f"{self.rc_name}_enable=YES"])
+
+    def disable(self, instance_name=""):
+        ipautil.run(["/usr/sbin/sysrc", f"{self.rc_name}_enable=NO"])
+
+    def install(self, instance_name=""):
+        return self.enable(instance_name)
+
+    def remove(self, instance_name=""):
+        return self.disable(instance_name)
+
+    def reload_or_restart(self, instance_name="", capture_output=True,
+                          wait=True):
+        self.restart(instance_name, capture_output, wait)
+
+
+class FreeBSDServices(base_services.KnownServices):
+    def __init__(self):
+        import ipalib
+        values = {
+            name: freebsd_service_class_factory(name, ipalib.api)
+            for name in base_services.wellknownservices
+        }
+        super().__init__(values)
+
+    @staticmethod
+    def service_class_factory(name, api=None):
+        return freebsd_service_class_factory(name, api)
+
+
+def freebsd_service_class_factory(name, api=None):
+    return FreeBSDService(name, api)
+
+
+timedate_services = base_services.timedate_services
+service = freebsd_service_class_factory
+knownservices = FreeBSDServices()
