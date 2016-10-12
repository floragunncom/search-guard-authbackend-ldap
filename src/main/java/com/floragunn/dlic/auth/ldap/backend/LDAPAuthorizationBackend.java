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

package com.floragunn.dlic.auth.ldap.backend;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.ldaptive.BindRequest;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.Credential;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.SearchScope;
import org.ldaptive.ssl.AllowAnyHostnameVerifier;
import org.ldaptive.ssl.CredentialConfig;
import org.ldaptive.ssl.CredentialConfigFactory;
import org.ldaptive.ssl.HostnameVerifyingTrustManager;
import org.ldaptive.ssl.SslConfig;

import com.floragunn.dlic.auth.ldap.LdapUser;
import com.floragunn.dlic.auth.ldap.util.ConfigConstants;
import com.floragunn.dlic.auth.ldap.util.LdapHelper;
import com.floragunn.dlic.auth.ldap.util.Utils;
import com.floragunn.searchguard.auth.AuthorizationBackend;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class LDAPAuthorizationBackend implements AuthorizationBackend {

    static final String JKS = "JKS";
    static final String PKCS12 = "PKCS12";
    static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";
    static final String ONE_PLACEHOLDER = "{1}";
    static final String TWO_PLACEHOLDER = "{2}";
    static final String DEFAULT_ROLEBASE = "";
    static final String DEFAULT_ROLESEARCH = "(member={0})";
    static final String DEFAULT_ROLENAME = "name";
    static final String DEFAULT_USERROLENAME = "memberOf";

    static {
        Utils.printLicenseInfo();
    }

    protected static final Logger log = LogManager.getLogger(LDAPAuthorizationBackend.class);
    final Settings settings;

    public LDAPAuthorizationBackend(final Settings settings) {
        this.settings = settings;
    }
    
    public static Connection getConnection(final Settings settings) throws Exception {
        
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Connection>() {
                @Override
                public Connection run() throws Exception {
                    return getConnection0(settings);
                }
            });
        } catch (PrivilegedActionException e) {
            throw e.getException();
        }

    }

    private static Connection getConnection0(final Settings settings) throws KeyStoreException, NoSuchAlgorithmException,
    CertificateException, FileNotFoundException, IOException, LdapException {
        final boolean enableSSL = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL, false);

        final String[] ldapHosts = settings.getAsArray(ConfigConstants.LDAP_HOSTS, new String[] { "localhost" });

        Connection connection = null;

        for (int i = 0; i < ldapHosts.length; i++) {
            
            if(log.isTraceEnabled()) {
                log.trace("Connect to {}", ldapHosts[i]);
            }

            try {

                final String[] split = ldapHosts[i].split(":");

                int port = 389;

                if (split.length > 1) {
                    port = Integer.parseInt(split[1]);
                } else {
                    port = enableSSL ? 636 : 389;
                }

                final ConnectionConfig config = new ConnectionConfig();
                config.setLdapUrl("ldap" + (enableSSL ? "s" : "") + "://" + split[0] + ":" + port);
                
                if(log.isTraceEnabled()) {
                    log.trace("Connect to {}", config.getLdapUrl());
                }
                
                Map<String, Object> props = configureSSL(config, settings);

                DefaultConnectionFactory connFactory = new DefaultConnectionFactory(config);
                connFactory.getProvider().getProviderConfig().setProperties(props);
                connection = connFactory.getConnection();
                
                final String bindDn = settings.get(ConfigConstants.LDAP_BIND_DN, null);
                final String password = settings.get(ConfigConstants.LDAP_PASSWORD, null);

                if (log.isDebugEnabled()) {
                    log.debug("bindDn {}, password {}", bindDn, password != null && password.length() > 0?"****":"<not set>");
                }
                
                if (bindDn != null && (password == null || password.length() == 0)) {
                    log.error("No password given for bind_dn {}. Will try to authenticate anonymously to ldap", bindDn);
                }
                
                BindRequest br = new BindRequest();
                
                if (bindDn != null && password != null && password.length() > 0) {
                    br = new BindRequest(bindDn, new Credential(password));
                }
                
                connection.open(br);

                if (connection != null && connection.isOpen()) {
                    break;
                }
            } catch (final Exception e) {
                log.warn("Unable to connect to ldapserver {} due to {}. Try next.", e, ldapHosts[i], e.toString());
                e.printStackTrace();
                Utils.unbindAndCloseSilently(connection);
                continue;
            }
        }

        if (connection == null || !connection.isOpen()) {
            throw new LdapException("Unable to connect to any of those ldap servers " + Arrays.toString(ldapHosts));
        }

        return connection;
    }

    private static Map<String, Object> configureSSL(final ConnectionConfig config, final Settings settings) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
        Map<String, Object> props = new HashMap<String, Object>();
        final boolean enableSSL = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL, false);
        final boolean enableStartTLS = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_START_TLS, false);

        if (enableSSL || enableStartTLS) {
            
            final boolean enableClientAuth = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH, false);
            final boolean verifyHostnames = settings.getAsBoolean(ConfigConstants.LDAPS_VERIFY_HOSTNAMES, true);
            
            final SslConfig sslConfig = new SslConfig();
            
            Environment env = new Environment(settings);
     
            File trustStore = env.configFile().resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH)).toFile();
            String truststorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD,DEFAULT_KEYSTORE_PASSWORD);
            
            File keystore = null;
            String keystorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD,DEFAULT_KEYSTORE_PASSWORD);        
        
            final String _keystore = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH);
            
            if(_keystore != null) {
                keystore = env.configFile().resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH)).toFile();
            }
            
            if (trustStore != null) {
                final KeyStore myTrustStore = KeyStore.getInstance(trustStore.getName().endsWith(JKS.toLowerCase()) ? JKS : PKCS12);
                myTrustStore.load(new FileInputStream(trustStore),
                        truststorePassword == null || truststorePassword.isEmpty() ? null : truststorePassword.toCharArray());
                
                if (enableClientAuth && keystore != null) {
                    final KeyStore keyStore = KeyStore.getInstance(keystore.getName().endsWith(JKS.toLowerCase()) ? JKS : PKCS12);
                    keyStore.load(new FileInputStream(keystore), keystorePassword == null || keystorePassword.isEmpty() ? null
                            : keystorePassword.toCharArray());
                    
                    CredentialConfig cc = CredentialConfigFactory.createKeyStoreCredentialConfig(myTrustStore, keyStore, keystorePassword);
                    sslConfig.setCredentialConfig(cc);
                } else {
                    CredentialConfig cc = CredentialConfigFactory.createKeyStoreCredentialConfig(myTrustStore);
                    sslConfig.setCredentialConfig(cc);
                }
                
            }

            if(enableStartTLS && !verifyHostnames) {
                props.put("jndi.starttls.allowAnyHostname", "true");
            }
            
            if(!verifyHostnames) {
                sslConfig.setTrustManagers(new HostnameVerifyingTrustManager(new AllowAnyHostnameVerifier(), "dummy"));
            }

            sslConfig.setEnabledProtocols(new String[] { "TLSv1.1", "TLSv1.2" });
            config.setSslConfig(sslConfig);
        }

        config.setUseSSL(enableSSL);
        config.setUseStartTLS(enableStartTLS);
        config.setConnectTimeout(5000L); // 5 sec
        return props;
        
    }

    @Override
    public void fillRoles(final User user, final AuthCredentials optionalAuthCreds) throws ElasticsearchSecurityException {

        String authenticatedUser;
        
        if(user instanceof LdapUser) {
            authenticatedUser = ((LdapUser) user).getUserEntry().getDn(); 
        } else {
            authenticatedUser =  Utils.escapeStringRfc2254(user.getName());
        }

        LdapEntry entry = null;
        String dn = null;
        Connection connection = null;

        try {

            connection = getConnection(settings);

            if (isValidDn(authenticatedUser)) {
                // assume dn
                if(log.isTraceEnabled()) {
                    log.trace("{} is a valid DN", authenticatedUser);
                }
                entry = LdapHelper.lookup(connection, authenticatedUser);

                if (entry == null) {
                    throw new ElasticsearchSecurityException("No user '" + authenticatedUser + "' found");
                }

            } else {
                
                entry = LDAPAuthenticationBackend.exists(user.getName(), connection, settings);
                
                if (entry == null) {
                    throw new ElasticsearchSecurityException("No user " + authenticatedUser + " found");
                }
            }

            dn = entry.getDn().toString();

            if(log.isTraceEnabled()) {
                log.trace("User found with DN {}", dn);
            }

            final Set<String> userRolesDn = new HashSet<String>();

            // Roles as an attribute of the user entry
            // Role names may also be held as the values of an attribute in the
            // user's directory entry. Use userRoleName to specify the name of
            // this attribute.
            final String userRoleName = settings
                    .get(ConfigConstants.LDAP_AUTHZ_USERROLENAME, DEFAULT_USERROLENAME);
            if (entry.getAttribute(userRoleName) != null) {
                final Collection<String> userRoles = entry.getAttribute(userRoleName).getStringValues();

                for (final String possibleRoleDN : userRoles) {
                    if (isValidDn(possibleRoleDN)) {
                        userRolesDn.add(possibleRoleDN);
                    }
                }

                if(log.isTraceEnabled()) {
                    log.trace("User roles count: {}", userRolesDn.size());
                }
            }

            final Map<Tuple<String, LdapName>, LdapEntry> roles = new HashMap<Tuple<String, LdapName>, LdapEntry>();
            final String roleName = settings.get(ConfigConstants.LDAP_AUTHZ_ROLENAME, DEFAULT_ROLENAME);

            // replace {2}
            final String userRoleAttribute = settings.get(ConfigConstants.LDAP_AUTHZ_USERROLEATTRIBUTE,
                    null);
            String userRoleAttributeValue = null;

            if (userRoleAttribute != null) {
                userRoleAttributeValue = entry.getAttribute(userRoleAttribute) == null ? null : entry.getAttribute(userRoleAttribute)
                        .getStringValue();
            }

            final List<LdapEntry> rolesResult = LdapHelper.search(
                    connection,
                    settings.get(ConfigConstants.LDAP_AUTHZ_ROLEBASE, DEFAULT_ROLEBASE),
                    settings.get(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, DEFAULT_ROLESEARCH)
                    .replace(LDAPAuthenticationBackend.ZERO_PLACEHOLDER, dn).replace(ONE_PLACEHOLDER, authenticatedUser)
                    .replace(TWO_PLACEHOLDER, userRoleAttributeValue == null ? TWO_PLACEHOLDER : userRoleAttributeValue), SearchScope.SUBTREE);

            if(rolesResult != null) {
                for (final Iterator<LdapEntry> iterator = rolesResult.iterator(); iterator.hasNext();) {
                    final LdapEntry searchResultEntry = iterator.next();
                    roles.put(new Tuple<String, LdapName>(searchResultEntry.getDn().toString(), new LdapName(searchResultEntry.getDn())),
                            searchResultEntry);
                }
            }
            

            if(log.isTraceEnabled()) {
                log.trace("non user roles count: {}", roles.size());
            }

            for (final Iterator<String> it = userRolesDn.iterator(); it.hasNext();) {
                final String stringVal = it.next();
                // lookup
                final LdapEntry userRole = LdapHelper.lookup(connection, stringVal);
                roles.put(new Tuple<String, LdapName>(stringVal, null), userRole);

            }

            // nested roles
            if (settings.getAsBoolean(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false)) {

                if(log.isTraceEnabled()) {
                    log.trace("Evaluate nested roles");
                }

                final Set<LdapEntry> nestedReturn = new HashSet<LdapEntry>(roles.values());

                for (final Iterator<java.util.Map.Entry<Tuple<String, LdapName>, LdapEntry>> iterator = roles.entrySet().iterator(); iterator
                        .hasNext();) {
                    final java.util.Map.Entry<Tuple<String, LdapName>, LdapEntry> _entry = iterator.next();

                    final Set<LdapEntry> x = resolveNestedRoles(_entry.getKey(), connection, roleName);

                    if(log.isTraceEnabled()) {
                        log.trace("{}. nested roles for {} {}", x.size(), _entry.getKey(), roleName);
                    }

                    nestedReturn.addAll(x);

                }

                for (final Iterator<LdapEntry> iterator = nestedReturn.iterator(); iterator.hasNext();) {
                    final LdapEntry entry2 = iterator.next();
                    final String role = entry2.getAttribute(roleName).getStringValue();
                    user.addRole(role);
                }

                if (user instanceof LdapUser) {
                    ((LdapUser) user).addRoleEntries(nestedReturn);
                }

            } else {

                for (final Iterator<LdapEntry> iterator = roles.values().iterator(); iterator.hasNext();) {
                    final LdapEntry entry2 = iterator.next();
                    final LdapAttribute e = entry2.getAttribute(roleName);
                    if (e != null) {
                        final String role = e.getStringValue();
                        user.addRole(role);
                    } else {
                        log.warn("No attribute '{}' for entry {}", roleName, entry2.getDn());
                    }

                }

                if (user instanceof LdapUser) {
                    ((LdapUser) user).addRoleEntries(roles.values());
                }
            }

        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new ElasticsearchSecurityException(e.toString(), e);
        } finally {
            Utils.unbindAndCloseSilently(connection);
        }

    }

    protected Set<LdapEntry> resolveNestedRoles(final Tuple<String, LdapName> role, final Connection ldapConnection, final String roleName)
            throws ElasticsearchSecurityException, LdapException {

        final Set<LdapEntry> result = new HashSet<LdapEntry>();
        LdapName roleDn = null;
        final boolean isRoleStringValidDn = isValidDn(role.v1());

        if (role.v2() != null) {
            roleDn = role.v2();
        } else {
            // lookup role
            if (isRoleStringValidDn) {
                try {
                    roleDn = new LdapName(LdapHelper.lookup(ldapConnection, role.v1()).getDn());
                } catch (final InvalidNameException e) {
                    throw new LdapException(e);
                }
            } else {

                try {

                    // search
                    final List<LdapEntry> _result = LdapHelper.search(
                            ldapConnection,
                            settings.get(ConfigConstants.LDAP_AUTHZ_ROLEBASE, DEFAULT_ROLEBASE),
                            settings.get(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, DEFAULT_ROLESEARCH).replace(
                                    ONE_PLACEHOLDER, role.v1()), SearchScope.SUBTREE);

                    // one
                    if (_result == null || _result.isEmpty()) {
                        log.warn("Cannot resolve role '{}' (NOT FOUND)", role.v1());
                    } else {

                        //
                        final LdapEntry entry = _result.get(0);
                        roleDn = new LdapName(entry.getDn());

                        if (_result.size() > 1) {
                            log.warn("Cannot resolve role '{}' (MORE THAN ONE FOUND)", role.v1());
                        }

                    }
                } catch (final InvalidNameException e) {
                    // log.warn("Cannot resolve role '{}' (EXCEPTION: {})", e,
                    // role.v1(), e.toString());
                    throw new LdapException(e);
                }

            }

        }

        if(log.isTraceEnabled()) {
            log.trace("role dn resolved to {}", roleDn);
        }

        final List<LdapEntry> rolesResult = LdapHelper.search(
                ldapConnection,
                settings.get(ConfigConstants.LDAP_AUTHZ_ROLEBASE, DEFAULT_ROLEBASE),
                settings.get(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, DEFAULT_ROLESEARCH)
                .replace(LDAPAuthenticationBackend.ZERO_PLACEHOLDER, roleDn == null ? role.v1() : roleDn.toString()).replace(ONE_PLACEHOLDER, role.v1()), SearchScope.SUBTREE);

        for (final Iterator<LdapEntry> iterator = rolesResult.iterator(); iterator.hasNext();) {
            final LdapEntry searchResultEntry = iterator.next();
            final String _role = searchResultEntry.getAttribute(roleName).getStringValue();
            
            if(log.isTraceEnabled()) {
                log.trace("nested l1 {}", searchResultEntry.getDn());
            }
            
            try {
                final Set<LdapEntry> in = resolveNestedRoles(new Tuple<String, LdapName>(_role, new LdapName(searchResultEntry.getDn())),
                        ldapConnection, roleName);

                for (final Iterator<LdapEntry> iterator2 = in.iterator(); iterator2.hasNext();) {
                    final LdapEntry entry = iterator2.next();
                    result.add(entry);
                    
                    if(log.isTraceEnabled()) {
                        log.trace("nested l2 {}", entry.getDn());
                    }
                }
            } catch (final InvalidNameException e) {
                throw new LdapException(e);
            }

            result.add(searchResultEntry);

        }

        return result;

    }

    @Override
    public String getType() {
        return "ldap";
    }

    private boolean isValidDn(final String dn) {

        if (Strings.isNullOrEmpty(dn)) {
            return false;
        }

        try {
            new LdapName(dn);
        } catch (final Exception e) {
            return false;
        }

        return true;
    }

}
