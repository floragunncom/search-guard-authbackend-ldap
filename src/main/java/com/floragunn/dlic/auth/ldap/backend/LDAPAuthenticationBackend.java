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

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.List;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.ldaptive.BindRequest;
import org.ldaptive.Connection;
import org.ldaptive.Credential;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.SearchScope;

import com.floragunn.dlic.auth.ldap.LdapUser;
import com.floragunn.dlic.auth.ldap.util.ConfigConstants;
import com.floragunn.dlic.auth.ldap.util.LdapHelper;
import com.floragunn.dlic.auth.ldap.util.Utils;
import com.floragunn.searchguard.auth.AuthenticationBackend;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class LDAPAuthenticationBackend implements AuthenticationBackend {

    static {
        Utils.printLicenseInfo();
    }

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;

    public LDAPAuthenticationBackend(final Settings settings) {
        this.settings = settings;
    }
    

    @Override
    public User authenticate(final AuthCredentials authCreds) throws ElasticsearchSecurityException {

        Connection ldapConnection = null;
        final String user = Utils.escapeStringRfc2254(authCreds.getUsername());
        byte[] password = authCreds.getPassword();

        try {

            ldapConnection = LDAPAuthorizationBackend.getConnection(settings);

            final List<LdapEntry> result = LdapHelper.search(ldapConnection,
                    settings.get(ConfigConstants.LDAP_AUTHC_USERBASE, ""),
                    settings.get(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(sAMAccountName={0})").replace("{0}", user),
                    SearchScope.SUBTREE);

            if (result == null || result.isEmpty()) {
                throw new ElasticsearchSecurityException("No user " + user + " found");
            }

            if (result.size() > 1) {
                throw new ElasticsearchSecurityException("More than one user found");
            }

            final LdapEntry entry = result.get(0);
            final String dn = entry.getDn();

            if(log.isTraceEnabled()) {
                log.trace("Try to authenticate dn {}", dn);
            }

            final BindRequest br = new BindRequest(dn, new Credential(password));

            
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }
            
            final Connection _con = ldapConnection;
            
            try {
                AccessController.doPrivileged(new PrivilegedExceptionAction<Response<Void>>() {
                    @Override
                    public Response<Void> run() throws LdapException {
                        return _con.reopen(br);
                    }
                });
            } catch (PrivilegedActionException e) {
                throw e.getException();
            }

            final String usernameAttribute = settings.get(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, null);
            String username = dn;

            if (usernameAttribute != null && entry.getAttribute(usernameAttribute) != null) {
                username = entry.getAttribute(usernameAttribute).getStringValue();
            }

            if(log.isDebugEnabled()) {
                log.debug("Authenticated username {}", username);
            }

            return new LdapUser(username, entry);

        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new ElasticsearchSecurityException(e.toString(), e);
        } finally {
            Arrays.fill(password, (byte) '\0');
            password = null;
            Utils.unbindAndCloseSilently(ldapConnection);
        }

    }

    @Override
    public String getType() {
        return "ldap";
    }

    @Override
    public boolean exists(final User user) {
        Connection ldapConnection = null;
        
        final String username = Utils.escapeStringRfc2254(user.getName());

        try {

            ldapConnection = LDAPAuthorizationBackend.getConnection(settings);

            final List<LdapEntry> result = LdapHelper.search(
                    ldapConnection,
                    settings.get(ConfigConstants.LDAP_AUTHC_USERBASE, ""),
                    settings.get(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(sAMAccountName={0})").replace("{0}",
                            username), SearchScope.SUBTREE);

            if (result == null || result.isEmpty()) {
                throw new ElasticsearchSecurityException("No user " + username + " found");
            }

            if (result.size() > 1) {
                throw new ElasticsearchSecurityException("More than one user for '" + username + "' found");
            }

        } catch (final Exception e) {
            log.error(e.toString(), e);
            return false;
        } finally {
            Utils.unbindAndCloseSilently(ldapConnection);
        }

        return true;
    }

}
