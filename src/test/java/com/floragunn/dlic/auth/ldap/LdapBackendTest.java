/*
 * Copyright 2016 by floragunn UG (haftungsbeschränkt) - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * This software is free of charge for non-commercial and academic use. 
 * For commercial use in a production environment you have to obtain a license 
 * from https://floragunn.com
 * 
 */

package com.floragunn.dlic.auth.ldap;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.TreeSet;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.ldaptive.Connection;
import org.ldaptive.LdapEntry;

import com.floragunn.dlic.auth.ldap.backend.LDAPAuthenticationBackend;
import com.floragunn.dlic.auth.ldap.backend.LDAPAuthorizationBackend;
import com.floragunn.dlic.auth.ldap.srv.EmbeddedLDAPServer;
import com.floragunn.dlic.auth.ldap.util.ConfigConstants;
import com.floragunn.dlic.auth.ldap.util.LdapHelper;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class LdapBackendTest {

    protected EmbeddedLDAPServer ldapServer = null;

    public final void startLDAPServer() throws Exception {

        // log.debug("non localhost address: {}", getNonLocalhostAddress());

        ldapServer = new EmbeddedLDAPServer();

        // keytab.delete();
        // ldapServer.createKeytab("krbtgt/EXAMPLE.COM@EXAMPLE.COM", "secret",
        // keytab);
        // ldapServer.createKeytab("HTTP/" + getNonLocalhostAddress() +
        // "@EXAMPLE.COM", "httppwd", keytab);
        // ldapServer.createKeytab("HTTP/localhost@EXAMPLE.COM", "httppwd",
        // keytab);
        // ldapServer.createKeytab("ldap/localhost@EXAMPLE.COM", "randall",
        // keytab);

        ldapServer.start();
        ldapServer.applyLdif("base.ldif");
    }

    @Test
    public void testLdapAuthentication() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }
    
    @Test(expected=ElasticsearchSecurityException.class)
    public void testLdapAuthenticationFakeLogin() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, true)
                .build();

        new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("unknown", "unknown"
                .getBytes(StandardCharsets.UTF_8)));
    }
    
    @Test(expected=ElasticsearchSecurityException.class)
    public void testLdapInjection() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        String injectString = "*jack*";

        
        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials(injectString, "secret"
                .getBytes(StandardCharsets.UTF_8)));
    }
    
    @Test
    public void testLdapAuthenticationBindDn() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS,  "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_BIND_DN, "cn=Captain Spock,ou=people,o=TEST")
                .put(ConfigConstants.LDAP_PASSWORD, "spocksecret")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }
    
    @Test(expected=ElasticsearchSecurityException.class)
    public void testLdapAuthenticationWrongBindDn() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS,  "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_BIND_DN, "cn=Captain Spock,ou=people,o=TEST")
                .put(ConfigConstants.LDAP_PASSWORD, "wrong")
                .build();

        new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
    }
    
    @Test(expected=ElasticsearchSecurityException.class)
    public void testLdapAuthenticationBindFail() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS,  "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "wrong".getBytes(StandardCharsets.UTF_8)));
    }
    
    @Test(expected=ElasticsearchSecurityException.class)
    public void testLdapAuthenticationNoUser() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS,  "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("UNKNOWN", "UNKNOWN".getBytes(StandardCharsets.UTF_8)));
    }

    @Test(expected = ElasticsearchSecurityException.class)
    public void testLdapAuthenticationFail() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "xxxxx".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testLdapAuthenticationSSL() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("verify_hostnames", false)
                .put("path.home",".")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }
    
    @Test
    public void testLdapAuthenticationSSLSSLv3() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("verify_hostnames", false)
                .putArray("enabled_ssl_protocols", "SSLv3")
                .put("path.home",".")
                .build();

        try {
            new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                    .getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            Assert.assertEquals(e.getCause().getClass(), org.ldaptive.LdapException.class);
            Assert.assertTrue(e.getCause().getMessage().contains("Unable to connec"));
        }
        
    }
    
    @Test
    public void testLdapAuthenticationSSLUnknowCipher() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("verify_hostnames", false)
                .putArray("enabled_ssl_ciphers", "AAA")
                .put("path.home",".")
                .build();

        try {
            new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                    .getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            Assert.assertEquals(e.getCause().getClass(), org.ldaptive.LdapException.class);
            Assert.assertTrue(e.getCause().getMessage().contains("Unable to connec"));
        }
        
    }
    
    @Test
    public void testLdapAuthenticationSpecialCipherProtocol() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("verify_hostnames", false)
                .putArray("enabled_ssl_protocols", "TLSv1")
                .putArray("enabled_ssl_ciphers", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA")
                .put("path.home",".")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
        
    }
    
    @Test
    public void testLdapAuthenticationSSLNoKeystore() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("verify_hostnames", false)
                .put("path.home",".")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthenticationSSLFailPlain() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_SSL, true).build();

        try {
            new LDAPAuthenticationBackend(settings)
                    .authenticate(new AuthCredentials("jacksonm", "secret".getBytes(StandardCharsets.UTF_8)));
        } catch (final Exception e) {
            Assert.assertEquals(org.ldaptive.LdapException.class, e.getCause().getClass());
        }
    }

    @Test
    public void testLdapExists() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        final LDAPAuthenticationBackend lbe = new LDAPAuthenticationBackend(settings);
        Assert.assertTrue(lbe.exists(new User("jacksonm")));
        Assert.assertFalse(lbe.exists(new User("doesnotexist")));
    }

    @Test
    public void testLdapAuthorization() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "127.0.0.1:4", "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                // .put("searchguard.authentication.authorization.ldap.userrolename",
                // "(uniqueMember={0})")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));

        new LDAPAuthorizationBackend(settings).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("ceo", new ArrayList(new TreeSet(user.getRoles())).get(0));
        Assert.assertEquals(2, user.getRoleEntries().size());
        Assert.assertEquals(user.getName(), user.getUserEntry().getDn());
    }

    @Test
    public void testLdapAuthenticationReferral() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})").build();

        final Connection con = LDAPAuthorizationBackend.getConnection(settings);
        try {
            final LdapEntry ref1 = LdapHelper.lookup(con, "cn=Ref1,ou=people,o=TEST");
            Assert.assertEquals("cn=refsolved,ou=people,o=TEST", ref1.getDn());
        } finally {
            con.close();
        }

    }
    
    
    @Test
    public void testLdapEscape() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("ssign", "ssignsecret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Special\\, Sign,ou=people,o=TEST", user.getName());
        new LDAPAuthorizationBackend(settings).fillRoles(user, null);
        Assert.assertEquals("cn=Special\\, Sign,ou=people,o=TEST", user.getName());
    }
    
    @Test
    public void testLdapAuthorizationRoleSearchUsername() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(cn={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember=cn={1},ou=people,o=TEST)")
                // .put("searchguard.authentication.authorization.ldap.userrolename",
                // "(uniqueMember={0})")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("Michael Jackson", "secret"
                .getBytes(StandardCharsets.UTF_8)));

        new LDAPAuthorizationBackend(settings).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("Michael Jackson", user.getOriginalUsername());
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getUserEntry().getDn());
        System.out.println(user.getRoles());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("ceo", new ArrayList(new TreeSet(user.getRoles())).get(0));
        Assert.assertEquals(2, user.getRoleEntries().size());
        Assert.assertEquals(user.getName(), user.getUserEntry().getDn());
    }
    
    @Test
    public void testLdapAuthorizationOnly() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .build();

        final User user = new User("jacksonm");

        new LDAPAuthorizationBackend(settings).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("jacksonm", user.getName());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("ceo", new ArrayList(new TreeSet(user.getRoles())).get(0));
    }
    
    @Test
    public void testLdapAuthorizationNested() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("spock", user.getName());
        Assert.assertEquals(4, user.getRoles().size());
        Assert.assertEquals("nested1", new ArrayList(new TreeSet(user.getRoles())).get(1));
        System.out.println(user.getRoles());
    }
    
    @Test
    public void testLdapAuthorizationDnNested() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "dn")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, true)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .build();

        final User user = new User("spock");

        new LDAPAuthorizationBackend(settings).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("spock", user.getName());
        Assert.assertEquals(4, user.getRoles().size());
        Assert.assertEquals("cn=nested1,ou=groups,o=TEST", new ArrayList(new TreeSet(user.getRoles())).get(1));
    }
    
    @Test
    public void testLdapAuthorizationDn() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "dn")
                .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "UID")
                .put(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false)
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")
                .build();

        final User user = new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret".getBytes()));

        new LDAPAuthorizationBackend(settings).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("jacksonm", user.getName());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("cn=ceo,ou=groups,o=TEST", new ArrayList(new TreeSet(user.getRoles())).get(0));
    }

    @Test
    public void testLdapAuthenticationUserNameAttribute() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder().putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST").put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid").build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("jacksonm", user.getName());
    }

    @Test
    public void testLdapAuthenticationStartTLS() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.builder()
                .putArray(ConfigConstants.LDAP_HOSTS, "localhost:" + EmbeddedLDAPServer.ldapPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAPS_ENABLE_START_TLS, true)
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("verify_hostnames", false).put("path.home", ".")
                .build();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }
    
    @After
    public void tearDown() throws Exception {

        if (ldapServer != null) {
            ldapServer.stop();
        }

    }

    public static File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        File file = null;
        final URL fileUrl = LdapBackendTest.class.getClassLoader().getResource(fileNameFromClasspath);
        if (fileUrl != null) {
            try {
                file = new File(URLDecoder.decode(fileUrl.getFile(), "UTF-8"));
            } catch (final UnsupportedEncodingException e) {
                return null;
            }

            if (file.exists() && file.canRead()) {
                return file;
            } else {
                System.err.println("Cannot read from {}, maybe the file does not exists? " + file.getAbsolutePath());
            }

        } else {
            System.err.println("Failed to load " + fileNameFromClasspath);
        }
        return null;
    }
}
