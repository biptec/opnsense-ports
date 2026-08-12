--- /dev/null	2026-08-09 12:59:06.445036886 +0000
+++ ipaplatform/freebsd/tasks.py
@@ -0,0 +1,93 @@
+import os
+import socket
+
+from ipaplatform.base.tasks import BaseTaskNamespace
+from ipapython import ipautil
+
+
+class FreeBSDTaskNamespace(BaseTaskNamespace):
+    """Safe client-side task hooks for FreeBSD.
+
+    Base images carry the FreeIPA software but are not enrolled. Operations
+    that would silently apply Linux PAM/auth semantics fail closed until a
+    dedicated FreeBSD enrollment implementation exists.
+    """
+
+    def restore_context(self, filepath, force=False):
+        return None
+
+    def check_selinux_status(self):
+        return False
+
+    def check_ipv6_stack_enabled(self):
+        return socket.has_ipv6
+
+    def detect_container(self):
+        return None
+
+    def reload_systemwide_ca_store(self):
+        return True
+
+    def platform_insert_ca_certs(self, ca_certs):
+        return False
+
+    def platform_remove_ca_certs(self):
+        return False
+
+    def backup_hostname(self, fstore, statestore):
+        statestore.backup_state("network", "hostname", socket.gethostname())
+
+    def restore_hostname(self, fstore, statestore):
+        hostname = statestore.get_state("network", "hostname")
+        if hostname:
+            self.set_hostname(hostname)
+
+    def set_hostname(self, hostname):
+        ipautil.run(["/bin/hostname", hostname])
+        ipautil.run(["/usr/sbin/sysrc", f"hostname={hostname}"])
+
+    def set_nisdomain(self, nisdomain):
+        binary = "/bin/domainname"
+        if not os.path.exists(binary):
+            return False
+        ipautil.run([binary, nisdomain])
+        return True
+
+    def restore_pre_ipa_client_configuration(self, fstore, statestore,
+                                             was_sssd_installed,
+                                             was_sssd_configured):
+        return True
+
+    def is_nosssd_supported(self):
+        return False
+
+    def is_mkhomedir_supported(self):
+        return False
+
+    def set_selinux_booleans(self, required_settings, backup_func=None):
+        return False
+
+    @staticmethod
+    def _unsupported_auth_stack():
+        raise NotImplementedError(
+            "FreeBSD PAM/NSS enrollment mutation is intentionally disabled"
+        )
+
+    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, statestore,
+                                  sudo=True, subid=False):
+        self._unsupported_auth_stack()
+
+    def modify_pam_to_use_krb5(self, statestore):
+        self._unsupported_auth_stack()
+
+    def backup_auth_configuration(self, path):
+        self._unsupported_auth_stack()
+
+    def restore_auth_configuration(self, path):
+        self._unsupported_auth_stack()
+
+    def migrate_auth_configuration(self, statestore):
+        self._unsupported_auth_stack()
+
+
+tasks = FreeBSDTaskNamespace()
