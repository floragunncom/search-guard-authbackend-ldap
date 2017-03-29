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

package com.floragunn.dlic.auth.ldap.util;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.List;

import org.elasticsearch.SpecialPermission;

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;

public class LdapHelper {

    public static List<SearchResultEntry> search(final LDAPConnection conn, final String baseDn, final String filter,
            final SearchScope searchScope, final String... attributes) throws LDAPException {

        final SearchRequest searchRequest = new SearchRequest(baseDn, SearchScope.SUB, DereferencePolicy.ALWAYS, 0, 0, false,
                filter, attributes);
        searchRequest.setFollowReferrals(Boolean.TRUE);
        final SearchResult searchResult = conn.search(searchRequest);
        return searchResult.getSearchEntries();

    }

    public static SearchResultEntry lookup(final LDAPConnection conn, final String dn) throws LDAPException {
        return conn.getEntry(dn);
    }

}
