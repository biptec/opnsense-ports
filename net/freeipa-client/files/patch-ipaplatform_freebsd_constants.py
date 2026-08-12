--- /dev/null	2026-08-09 12:59:06.445036886 +0000
+++ ipaplatform/freebsd/constants.py
@@ -0,0 +1,28 @@
+from ipaplatform.base.constants import BaseConstantsNamespace, Group, User
+
+
+__all__ = ("constants", "User", "Group")
+
+
+class FreeBSDConstantsNamespace(BaseConstantsNamespace):
+    DEFAULT_ADMIN_SHELL = "/bin/sh"
+    HTTPD_USER = User("www")
+    HTTPD_GROUP = Group("www")
+    NAMED_USER = User("bind")
+    NAMED_GROUP = Group("bind")
+    NOBODY_GROUP = Group("nobody")
+    SSSD_USER = User("root")
+    SECURE_NFS_VAR = "gssd_enable"
+
+    # FreeBSD has no SELinux. Keep the public data shape FreeIPA expects,
+    # while platform tasks below make every SELinux operation a no-op.
+    SELINUX_BOOLEAN_ADTRUST = {}
+    SELINUX_BOOLEAN_HTTPD = {}
+    SELINUX_BOOLEAN_SMBSERVICE = {
+        "share_home_dirs": {},
+        "reshare_nfs_with_samba": {},
+    }
+    SELINUX_BOOLEAN_SSSD = {}
+
+
+constants = FreeBSDConstantsNamespace()
