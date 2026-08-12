--- /dev/null	2026-08-09 12:59:06.445036886 +0000
+++ ipaplatform/freebsd/paths.py
@@ -0,0 +1,87 @@
+from ipaplatform.base.paths import BasePathNamespace
+
+
+class FreeBSDPathNamespace(BasePathNamespace):
+    """Client-side paths for FreeBSD ports and OPNsense."""
+
+    ETC_IPA = "/usr/local/etc/ipa"
+    IPA_CA_CRT = ETC_IPA + "/ca.crt"
+    IPA_DEFAULT_CONF = ETC_IPA + "/default.conf"
+    IPA_NSSDB_DIR = ETC_IPA + "/nssdb"
+
+    COMMON_KRB5_CONF_DIR = "/usr/local/etc/krb5.conf.d/"
+    KRB5_CONF = "/usr/local/etc/krb5.conf"
+    KRB5_FREEIPA_DEFAULTS = COMMON_KRB5_CONF_DIR + "freeipa"
+    KRB5_FREEIPA = COMMON_KRB5_CONF_DIR + "freeipa-realm"
+    KRB5_FREEIPA_SERVER = COMMON_KRB5_CONF_DIR + "freeipa-server"
+    KRB5_KEYTAB = "/etc/krb5.keytab"
+
+    OPENLDAP_LDAP_CONF = "/usr/local/etc/openldap/ldap.conf"
+    SSSD_CONF = "/usr/local/etc/sssd/sssd.conf"
+    SSSD_CONF_BKP = SSSD_CONF + ".bkp"
+    SSSD_CONF_DELETED = SSSD_CONF + ".deleted"
+
+    USR_SHARE_IPA_DIR = "/usr/local/share/ipa/"
+    USR_SHARE_IPA_CLIENT_DIR = "/usr/local/share/ipa/client"
+    SSH_IPA_CONFIG_TEMPLATE = USR_SHARE_IPA_CLIENT_DIR + "/ssh_ipa.conf.template"
+    SSHD_IPA_CONFIG_TEMPLATE = USR_SHARE_IPA_CLIENT_DIR + "/sshd_ipa.conf.template"
+    UNBOUND_CONF_SRC = USR_SHARE_IPA_CLIENT_DIR + "/unbound.conf.template"
+
+    BIN_CURL = "/usr/local/bin/curl"
+    KDESTROY = "/usr/local/bin/kdestroy"
+    KINIT = "/usr/local/bin/kinit"
+    KLIST = "/usr/local/bin/klist"
+    KTUTIL = "/usr/local/bin/ktutil"
+    BIN_KVNO = "/usr/local/bin/kvno"
+    LDAPMODIFY = "/usr/local/bin/ldapmodify"
+    LDAPPASSWD = "/usr/local/bin/ldappasswd"
+    MODUTIL = "/usr/local/bin/modutil"
+    NSUPDATE = "/usr/local/bin/nsupdate"
+    PK12UTIL = "/usr/local/bin/pk12util"
+    CERTUTIL = "/usr/local/bin/certutil"
+
+    SSS_SSH_AUTHORIZEDKEYS = "/usr/local/bin/sss_ssh_authorizedkeys"
+    SSS_SSH_KNOWNHOSTS = "/usr/local/bin/sss_ssh_knownhosts"
+    SSS_SSH_KNOWNHOSTSPROXY = "/usr/local/bin/sss_ssh_knownhostsproxy"
+    SSSCTL = "/usr/local/sbin/sssctl"
+
+    IPA_CLIENT_AUTOMOUNT = "/usr/local/sbin/ipa-client-automount"
+    IPA_CLIENT_INSTALL = "/usr/local/sbin/ipa-client-install"
+    SBIN_IPA_JOIN = "/usr/local/sbin/ipa-join"
+    IPA_GETKEYTAB = "/usr/local/sbin/ipa-getkeytab"
+    IPA_RMKEYTAB = "/usr/local/sbin/ipa-rmkeytab"
+
+    SBIN_SERVICE = "/usr/sbin/service"
+    SSHD = "/usr/local/sbin/sshd"
+    NOLOGIN = "/usr/sbin/nologin"
+    NET = "/usr/local/bin/net"
+    SMBD = "/usr/local/sbin/smbd"
+    SMB_CONF = "/usr/local/etc/smb4.conf"
+    SAMBA_KEYTAB = "/var/db/samba4/samba.keytab"
+    SAMBA_DIR = "/var/db/samba4"
+    SAMBA_LOCKDIR = "/var/db/samba4"
+    KRB5CC_SAMBA = "/var/run/samba4/krb5cc_samba"
+
+    SSSD_DB = "/var/db/sss/db"
+    SSSD_MC_GROUP = "/var/db/sss/mc/group"
+    SSSD_MC_PASSWD = "/var/db/sss/mc/passwd"
+    SSSD_MC_INITGROUPS = "/var/db/sss/mc/initgroups"
+    SSSD_MC_SID = "/var/db/sss/mc/sid"
+    SSSD_PIPES = "/var/run/sssd"
+    SSSD_LDB = "/var/db/sss/db/sssd.ldb"
+    SSSD_CONFIG_LDB = "/var/db/sss/db/config.ldb"
+    SSSD_SECRETS = "/var/lib/sss/secrets/secrets.ldb"
+    SSSD_PUBCONF_DIR = "/var/db/sss/pubconf"
+    SSSD_PUBCONF_KNOWN_HOSTS = SSSD_PUBCONF_DIR + "/known_hosts"
+    SSSD_PUBCONF_KRB5_INCLUDE_D_DIR = SSSD_PUBCONF_DIR + "/krb5.include.d/"
+    SSSD_KEYTABS_DIR = "/var/db/sss/keytabs"
+
+    VAR_LIB = "/var/db"
+    IPA_CLIENT_SYSRESTORE = "/var/db/ipa-client/sysrestore"
+    SYSRESTORE_INDEX = IPA_CLIENT_SYSRESTORE + "/sysrestore.index"
+    CA_BUNDLE_PEM = "/var/db/ipa-client/pki/ca-bundle.pem"
+    KDC_CA_BUNDLE_PEM = "/var/db/ipa-client/pki/kdc-ca-bundle.pem"
+    SVC_LIST_FILE = "/var/run/ipa/services.list"
+
+
+paths = FreeBSDPathNamespace()
