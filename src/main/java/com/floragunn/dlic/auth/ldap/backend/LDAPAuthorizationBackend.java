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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.ArrayList;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.Strings;
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
import org.ldaptive.sasl.ExternalConfig;
import org.ldaptive.ssl.AllowAnyHostnameVerifier;
import org.ldaptive.ssl.CredentialConfig;
import org.ldaptive.ssl.CredentialConfigFactory;
import org.ldaptive.ssl.HostnameVerifyingTrustManager;
import org.ldaptive.ssl.SslConfig;

import com.floragunn.dlic.auth.ldap.LdapUser;
import com.floragunn.dlic.auth.ldap.util.ConfigConstants;
import com.floragunn.dlic.auth.ldap.util.LdapHelper;
import com.floragunn.dlic.auth.ldap.util.PemKeyReader;
import com.floragunn.dlic.auth.ldap.util.Utils;
import com.floragunn.searchguard.auth.AuthorizationBackend;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class LDAPAuthorizationBackend implements AuthorizationBackend {

    private static final String[] EMPTY_STRING_ARRAY = new String[0];
    static final String JKS = "JKS";
    static final String PKCS12 = "PKCS12";
    static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";
    static final String DEFAULT_TRUSTSTORE_PASSWORD = "changeit";
    static final String ONE_PLACEHOLDER = "{1}";
    static final String TWO_PLACEHOLDER = "{2}";
    static final String DEFAULT_ROLEBASE = "";
    static final String DEFAULT_ROLESEARCH = "(member={0})";
    static final String DEFAULT_ROLENAME = "name";
    static final String DEFAULT_USERROLENAME = "memberOf";

    static {
        Utils.init();
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
                
                final Map<String, Object> props = configureSSL(config, settings);

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
                
                final boolean enableClientAuth = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH, ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH_DEFAULT);

                if(log.isDebugEnabled()) {
                    if(enableClientAuth && bindDn == null) {
                        log.debug("Will perform External SASL bind because client cert authentication is enabled");
                    } else if(bindDn == null) {
                        log.debug("Will perform anonymous bind because to bind dn is given");
                    } else if(enableClientAuth && bindDn != null) {
                        log.debug("Will perform simple bind with bind dn because to bind dn is given and overrides client cert authentication");
                    } else if(!enableClientAuth && bindDn != null) {
                        log.debug("Will perform simple bind with bind dn");
                    }
                }
                
                BindRequest br = enableClientAuth?new BindRequest(new ExternalConfig()):new BindRequest();
                
                if (bindDn != null && password != null && password.length() > 0) {
                    br = new BindRequest(bindDn, new Credential(password));
                }
                
                connection.open(br);

                if (connection != null && connection.isOpen()) {
                    break;
                }
            } catch (final Exception e) {
                log.warn("Unable to connect to ldapserver {} due to {}. Try next.", ldapHosts[i], e.toString());
                if(log.isDebugEnabled()) {
                    log.debug("Unable to connect to ldapserver due to ",e);
                }
                Utils.unbindAndCloseSilently(connection);
                continue;
            }
        }

        if (connection == null || !connection.isOpen()) {
            throw new LdapException("Unable to connect to any of those ldap servers " + Arrays.toString(ldapHosts));
        }

        return connection;
    }
    
    private static void checkPath(String keystoreFilePath, String fileNameLogOnly) {
        
        if (keystoreFilePath == null || keystoreFilePath.length() == 0) {
            throw new ElasticsearchException("Empty file path for "+fileNameLogOnly);
        }
        
        if (Files.isDirectory(Paths.get(keystoreFilePath), LinkOption.NOFOLLOW_LINKS)) {
            throw new ElasticsearchException("Is a directory: " + keystoreFilePath+" Expected a file for "+fileNameLogOnly);
        }

        if(!Files.isReadable(Paths.get(keystoreFilePath))) {
            throw new ElasticsearchException("Unable to read " + keystoreFilePath + " ("+Paths.get(keystoreFilePath)+"). Please make sure this files exists and is readable regarding to permissions. Property: "+fileNameLogOnly);
        }
    }
    
    private static InputStream resolveStream(String propName, Settings settings) {
        final String content = settings.get(propName, null);
        
        if(content == null) {
            return null;
        }

        return new ByteArrayInputStream(content.getBytes(StandardCharsets.US_ASCII));
    }
    
    private static String resolve(String propName, Settings settings, boolean mustBeValid) {
        
        final String originalPath = settings.get(propName, null);
        String path = originalPath;
        log.debug("Value for {} is {}", propName, originalPath);
        final Environment env = new Environment(settings);
        
        if(env != null && originalPath != null && originalPath.length() > 0) {
            path = env.configFile().resolve(originalPath).toAbsolutePath().toString();
            log.debug("Resolved {} to {} against {}", originalPath, path, env.configFile().toAbsolutePath().toString());
        }
        
        if(mustBeValid) {
            checkPath(path, propName);
        }
        
        if("".equals(path)) {
            path = null;
        }
        
        return path;
    }
    
    private static PrivateKey loadKeyFromFile(String password, String keyFile) throws Exception {
        
        if(keyFile == null) {
            return null;
        }
        
        return PemKeyReader.toPrivateKey(new File(keyFile), password);
    }
    
    private static PrivateKey loadKeyFromStream(String password, InputStream in) throws Exception {
        
        if(in == null) {
            return null;
        }
        
        return PemKeyReader.toPrivateKey(in, password);
    }
    
    private static X509Certificate[] loadCertificatesFromFile(String file) throws Exception {
        if(file == null) {
            return null;
        }
        
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try(FileInputStream is = new FileInputStream(file)) {
            Collection<? extends Certificate> certs = fact.generateCertificates(is);
            X509Certificate[] x509Certs = new X509Certificate[certs.size()];
            int i=0;
            for(Certificate cert: certs) {
                x509Certs[i++] = (X509Certificate) cert;
            }
            return x509Certs;
        }
        
    }
    
    private static X509Certificate[] loadCertificatesFromStream(InputStream in) throws Exception {
        if(in == null) {
            return null;
        }
        
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certs = fact.generateCertificates(in);
        X509Certificate[] x509Certs = new X509Certificate[certs.size()];
        int i=0;
        for(Certificate cert: certs) {
            x509Certs[i++] = (X509Certificate) cert;
        }
        return x509Certs;
        
    }
    
    private static X509Certificate loadCertificateFromFile(String file) throws Exception {
        if(file == null) {
            return null;
        }
        
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try(FileInputStream is = new FileInputStream(file)) {
            return (X509Certificate) fact.generateCertificate(is);
        }
    }
    
    private static X509Certificate loadCertificateFromStream(InputStream in) throws Exception {
        if(in == null) {
            return null;
        }
        
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        return (X509Certificate) fact.generateCertificate(in);
    }
    
    private static KeyStore loadKeyStore(String storePath, String keyStorePassword, String type) throws Exception {
      if(storePath == null) {
          return null;
      }

      if(type == null || !type.toUpperCase().equals(JKS) || !type.toUpperCase().equals(PKCS12)) {
          type = JKS;
      }
      
      final KeyStore store = KeyStore.getInstance(type.toUpperCase());
      store.load(new FileInputStream(storePath), keyStorePassword==null?null:keyStorePassword.toCharArray());
      return store;
    }

    private static Map<String, Object> configureSSL(final ConnectionConfig config, final Settings settings) throws Exception {
        
        final Map<String, Object> props = new HashMap<String, Object>();
        final boolean enableSSL = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL, false);
        final boolean enableStartTLS = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_START_TLS, false);

        if (enableSSL || enableStartTLS) {
            
            final boolean enableClientAuth = settings.getAsBoolean(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH, ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH_DEFAULT);
            final boolean verifyHostnames = settings.getAsBoolean(ConfigConstants.LDAPS_VERIFY_HOSTNAMES, ConfigConstants.LDAPS_VERIFY_HOSTNAMES_DEFAULT);
            
            if(enableStartTLS && !verifyHostnames) {
                props.put("jndi.starttls.allowAnyHostname", "true");
            }
            
            final boolean pem = settings.get(ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH, null) != null
                    || settings.get(ConfigConstants.LDAPS_PEMTRUSTEDCAS_CONTENT, null) != null;
            
            final SslConfig sslConfig = new SslConfig();
            CredentialConfig cc;
            
            if(pem) {
                X509Certificate[] trustCertificates = loadCertificatesFromStream(resolveStream(ConfigConstants.LDAPS_PEMTRUSTEDCAS_CONTENT, settings));
                
                if(trustCertificates == null) {
                    trustCertificates = loadCertificatesFromFile(resolve(ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH, settings, true));
                }
                    //for client authentication
                X509Certificate authenticationCertificate = loadCertificateFromStream(resolveStream(ConfigConstants.LDAPS_PEMCERT_CONTENT, settings));
                
                if(authenticationCertificate == null) {
                    authenticationCertificate = loadCertificateFromFile(resolve(ConfigConstants.LDAPS_PEMCERT_FILEPATH, settings, enableClientAuth));
                }
                
                PrivateKey authenticationKey = loadKeyFromStream(settings.get(ConfigConstants.LDAPS_PEMKEY_PASSWORD), resolveStream(ConfigConstants.LDAPS_PEMKEY_CONTENT, settings));
                
                if(authenticationKey == null) {
                    authenticationKey = loadKeyFromFile(settings.get(ConfigConstants.LDAPS_PEMKEY_PASSWORD), resolve(ConfigConstants.LDAPS_PEMKEY_FILEPATH, settings, enableClientAuth));    
                }

                cc = CredentialConfigFactory.createX509CredentialConfig(trustCertificates, authenticationCertificate, authenticationKey);
                
                if(log.isDebugEnabled()) {
                    log.debug("Use PEM to secure communication with LDAP server (client auth is {})", authenticationKey!=null);
                }
                
            } else {
                final KeyStore trustStore = loadKeyStore(resolve(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, settings, true)
                        , settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, DEFAULT_TRUSTSTORE_PASSWORD)
                        , settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_TYPE));
                
                final String[] trustStoreAliases = settings.getAsArray(ConfigConstants.LDAPS_JKS_TRUST_ALIAS, null);
                
                //for client authentication
                final KeyStore keyStore = loadKeyStore(resolve(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, settings, enableClientAuth)
                        , settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, DEFAULT_KEYSTORE_PASSWORD)
                        , settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE));
                final String keyStorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, DEFAULT_KEYSTORE_PASSWORD);
                
                final String keyStoreAlias = settings.get(ConfigConstants.LDAPS_JKS_CERT_ALIAS, null);
                final String[] keyStoreAliases = keyStoreAlias==null?null:new String[]{keyStoreAlias};
                
                if(enableClientAuth && keyStoreAliases == null) {
                    throw new IllegalArgumentException(ConfigConstants.LDAPS_JKS_CERT_ALIAS+" not given");
                }
                
                if(log.isDebugEnabled()) {
                    log.debug("Use Trust-/Keystore to secure communication with LDAP server (client auth is {})", keyStore!=null);
                    log.debug("trustStoreAliases: {}, keyStoreAlias: {}",  Arrays.toString(trustStoreAliases), keyStoreAlias);
                }
                
                cc = CredentialConfigFactory.createKeyStoreCredentialConfig(trustStore, trustStoreAliases, keyStore, keyStorePassword, keyStoreAliases);

            }
            
            sslConfig.setCredentialConfig(cc);
            
            if(!verifyHostnames) {
                sslConfig.setTrustManagers(new HostnameVerifyingTrustManager(new AllowAnyHostnameVerifier(), "dummy"));
            }
       
            //https://github.com/floragunncom/search-guard/issues/227
            final String[] enabledCipherSuites = settings.getAsArray(ConfigConstants.LDAPS_ENABLED_SSL_CIPHERS, EMPTY_STRING_ARRAY);   
            final String[] enabledProtocols = settings.getAsArray(ConfigConstants.LDAPS_ENABLED_SSL_PROTOCOLS, new String[] { "TLSv1.1", "TLSv1.2" });   
            

            if(enabledCipherSuites.length > 0) {
                sslConfig.setEnabledCipherSuites(enabledCipherSuites);
                log.debug("enabled ssl cipher suites for ldaps {}", Arrays.toString(enabledCipherSuites));
            }
            
            log.debug("enabled ssl/tls protocols for ldaps {}", Arrays.toString(enabledProtocols));
            sslConfig.setEnabledProtocols(enabledProtocols);
            config.setSslConfig(sslConfig);
        }

        config.setUseSSL(enableSSL);
        config.setUseStartTLS(enableStartTLS);
        config.setConnectTimeout(5000L); // 5 sec
        
        return props;
        
    }

    @Override
    public void fillRoles(final User user, final AuthCredentials optionalAuthCreds) throws ElasticsearchSecurityException {

        if(user == null) {
            return;
        }
                
        String authenticatedUser;
        String originalUserName;
        LdapEntry entry = null;
        String dn = null;
        
        if(user instanceof LdapUser) {
            entry = ((LdapUser) user).getUserEntry();
            authenticatedUser = entry.getDn(); 
            originalUserName = ((LdapUser) user).getOriginalUsername();
        } else {
            authenticatedUser =  Utils.escapeStringRfc2254(user.getName());
            originalUserName = user.getName();
        }
        
        final boolean rolesearchEnabled = settings.getAsBoolean(ConfigConstants.LDAP_AUTHZ_ROLESEARCH_ENABLED, true);

        
        if(log.isTraceEnabled()) {
            log.trace("user class: {}", user.getClass());
            log.trace("authenticatedUser: {}", authenticatedUser);
            log.trace("originalUserName: {}", originalUserName);
            log.trace("entry: {}", String.valueOf(entry));
            log.trace("dn: {}", dn);
        }

        final String[] skipUsers = settings.getAsArray(ConfigConstants.LDAP_AUTHZ_SKIP_USERS, EMPTY_STRING_ARRAY);
        if (skipUsers.length > 0 && WildcardMatcher.matchAny(skipUsers, authenticatedUser)) {
            if (log.isDebugEnabled()) {
                log.debug("Skipped search roles of user {}", authenticatedUser);
            }
            return;
        }
       
        Connection connection = null;

        try {

            if(entry == null || dn == null) {
            
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
                    
                    if(log.isTraceEnabled()) {
                        log.trace("{} is not a valid DN and was resolved to {}", authenticatedUser, entry);
                    }
                    
                    if (entry == null || entry.getDn() == null) {
                        throw new ElasticsearchSecurityException("No user " + authenticatedUser + " found");
                    }
                }
    
                dn = entry.getDn();
    
                if(log.isTraceEnabled()) {
                    log.trace("User found with DN {}", dn);
                }
            }

            final Set<LdapName> roles = new HashSet<LdapName>(150);

            // Roles as an attribute of the user entry
            // default is userrolename: memberOf
            final String userRoleName = settings
                    .get(ConfigConstants.LDAP_AUTHZ_USERROLENAME, DEFAULT_USERROLENAME);
            
            if(log.isTraceEnabled()) {
                log.trace("userRoleName: {}", userRoleName);
            }
            
            if (entry.getAttribute(userRoleName) != null) {
                final Collection<String> userRoles = entry.getAttribute(userRoleName).getStringValues();

                for (final String possibleRoleDN : userRoles) {
                    if (isValidDn(possibleRoleDN)) {
                        roles.add(new LdapName(possibleRoleDN));
                    } else {
                        if(log.isDebugEnabled()) {
                            log.debug("Cannot add {} as a role because its not a valid dn", possibleRoleDN);
                        }
                    }
                }
            }
            
            if(log.isTraceEnabled()) {
                log.trace("User attr. roles count: {}", roles.size());
                log.trace("User attr. roles {}", roles);
            }

            // The attribute in a role entry containing the name of that role, Default is "name".
            // Can also be "dn" to use the full DN as rolename.
            // rolename: name
            final String roleName = settings.get(ConfigConstants.LDAP_AUTHZ_ROLENAME, DEFAULT_ROLENAME);
            
            if(log.isTraceEnabled()) {
                log.trace("roleName: {}", roleName);
            }

            // Specify the name of the attribute which value should be substituted with {2}
            // Substituted with an attribute value from user's directory entry, of the authenticated user
            // userroleattribute: null
            final String userRoleAttributeName = settings.get(ConfigConstants.LDAP_AUTHZ_USERROLEATTRIBUTE, null);
            
            if(log.isTraceEnabled()) {
                log.trace("userRoleAttribute: {}", userRoleAttributeName);
                log.trace("rolesearch: {}", settings.get(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, DEFAULT_ROLESEARCH));
            }
            
            String userRoleAttributeValue = null;
            final LdapAttribute userRoleAttribute = entry.getAttribute(userRoleAttributeName);

            if (userRoleAttribute != null) {
                userRoleAttributeValue = userRoleAttribute.getStringValue();
            }

            final List<LdapEntry> rolesResult = !rolesearchEnabled?null:LdapHelper.search(
                    connection,
                    settings.get(ConfigConstants.LDAP_AUTHZ_ROLEBASE, DEFAULT_ROLEBASE),
                    settings.get(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, DEFAULT_ROLESEARCH)
                    .replace(LDAPAuthenticationBackend.ZERO_PLACEHOLDER, Utils.escapeStringRfc2254(dn)).replace(ONE_PLACEHOLDER, originalUserName)
                    .replace(TWO_PLACEHOLDER, userRoleAttributeValue == null ? TWO_PLACEHOLDER : userRoleAttributeValue), SearchScope.SUBTREE);
            
            if(rolesResult != null && !rolesResult.isEmpty()) {
                for (final Iterator<LdapEntry> iterator = rolesResult.iterator(); iterator.hasNext();) {
                    final LdapEntry searchResultEntry = iterator.next();
                    roles.add(new LdapName(searchResultEntry.getDn()));
                }
            }

            if(log.isTraceEnabled()) {
                log.trace("non user attr. roles count: {}", rolesResult != null?rolesResult.size():0);
                log.trace("non user attr. roles {}", rolesResult);
                log.trace("roles count total {}", roles.size());
            }
            
            final String[] nestedRoleFilter = settings.getAsArray(ConfigConstants.LDAP_AUTHZ_NESTEDROLEFILTER, EMPTY_STRING_ARRAY);

            // nested roles
            if (settings.getAsBoolean(ConfigConstants.LDAP_AUTHZ_RESOLVE_NESTED_ROLES, false)) {

                if(log.isTraceEnabled()) {
                    log.trace("Evaluate nested roles");
                }

                final Set<LdapName> nestedReturn = new HashSet<LdapName>(roles);

                for (final LdapName roleLdapName: roles) {

                    final Set<LdapName> nestedRoles = resolveNestedRoles(roleLdapName, connection, userRoleName, 0, rolesearchEnabled, nestedRoleFilter);

                    if(log.isTraceEnabled()) {
                        log.trace("{} nested roles for {}", nestedRoles.size(), roleLdapName);
                    }

                    nestedReturn.addAll(nestedRoles);
                }

                for (final LdapName roleLdapName: nestedReturn) {
                    final String role = getRoleFromAttribute(roleLdapName, roleName);
                    
                    if(!Strings.isNullOrEmpty(role)) {
                        user.addRole(role);
                    } else {
                        log.warn("No or empty attribute '{}' for entry {}", roleName, roleLdapName);
                    }
                }

                /*
                if (user instanceof LdapUser) {
                    ((LdapUser) user).addRoleEntries(nestedReturn);
                }*/

            } else {

                for (final LdapName roleLdapName: roles) {
                    final String role = getRoleFromAttribute(roleLdapName, roleName);
                    
                    if(!Strings.isNullOrEmpty(role)) {
                        user.addRole(role);
                    } else {
                        log.warn("No or empty attribute '{}' for entry {}", roleName, roleLdapName);
                    }
                }

                /*if (user instanceof LdapUser) {
                    ((LdapUser) user).addRoleEntries(roles.values());
                }*/
            }
            

            if(log.isTraceEnabled()) {
                log.trace("returned user: {}", user);
            }

        } catch (final Exception e) {
            if(log.isDebugEnabled()) {
                log.debug("Unable to fill user roles due to ",e);
            }
            throw new ElasticsearchSecurityException(e.toString(), e);
        } finally {
            Utils.unbindAndCloseSilently(connection);
        }

    }

    protected Set<LdapName> resolveNestedRoles(final LdapName roleDn, final Connection ldapConnection, String userRoleName,
            int depth, final boolean rolesearchEnabled, final String[] roleFilter)
            throws ElasticsearchSecurityException, LdapException {
        
        if(roleFilter.length > 0  && WildcardMatcher.matchAny(roleFilter, roleDn.toString())) {
            
            if(log.isTraceEnabled()) {
                log.trace("Filter nested role {}", roleDn);
            }
            
            return Collections.emptySet();
        }
              
        depth++;

        final Set<LdapName> result = new HashSet<LdapName>(20);

        final LdapEntry e0 = LdapHelper.lookup(ldapConnection, roleDn.toString());

        if (e0.getAttribute(userRoleName) != null) {
            final Collection<String> userRoles = e0.getAttribute(userRoleName).getStringValues();

            for (final String possibleRoleDN : userRoles) {
                if (isValidDn(possibleRoleDN)) {
                    try {
                        result.add(new LdapName(possibleRoleDN));
                    } catch (InvalidNameException e) {
                        // ignore
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Cannot add {} as a role because its not a valid dn", possibleRoleDN);
                    }
                }
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("result nested attr count for depth {} : {}", depth, result.size());
        }
        
        final String escapedDn = Utils.escapeStringRfc2254(roleDn.toString());

        final List<LdapEntry> rolesResult = !rolesearchEnabled?null:LdapHelper
                .search(ldapConnection,
                        settings.get(ConfigConstants.LDAP_AUTHZ_ROLEBASE, DEFAULT_ROLEBASE),
                        settings.get(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, DEFAULT_ROLESEARCH)
                                .replace(LDAPAuthenticationBackend.ZERO_PLACEHOLDER, escapedDn)
                                .replace(ONE_PLACEHOLDER, escapedDn), SearchScope.SUBTREE);

        if (log.isTraceEnabled()) {
            log.trace("result nested search count for depth {}: {}", depth, rolesResult==null?0:rolesResult.size());
        }

        
        if(rolesResult != null) {
            for (final LdapEntry entry : rolesResult) {
                try {
                    final LdapName dn = new LdapName(entry.getDn());
                    result.add(dn);
                } catch (final InvalidNameException e) {
                    throw new LdapException(e);
                }
            }
        }

        for (final LdapName nm : new HashSet<LdapName>(result)) {
            final Set<LdapName> in = resolveNestedRoles(nm, ldapConnection, userRoleName, depth, rolesearchEnabled, roleFilter);
            result.addAll(in);
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
    
    private String getRoleFromAttribute(final LdapName ldapName, final String role) {

        if (ldapName == null || Strings.isNullOrEmpty(role)) {
            return null;
        }

        if("dn".equalsIgnoreCase(role)) {
            return ldapName.toString();
        }

        List<Rdn> rdns = new ArrayList<>(ldapName.getRdns().size());
        rdns.addAll(ldapName.getRdns());

        Collections.reverse(rdns);
        
        for(Rdn rdn: rdns) {
            if(role.equalsIgnoreCase(rdn.getType())) {
                
                if(rdn.getValue() == null) {
                    return null;
                }
                
                return String.valueOf(rdn.getValue());
            }
        }
        
        return null;
    }

}
