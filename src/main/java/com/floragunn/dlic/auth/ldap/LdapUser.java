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

import com.floragunn.searchguard.user.User;
import com.unboundid.ldap.sdk.SearchResultEntry;

public class LdapUser extends User {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    private final transient SearchResultEntry userEntry;
    private final String originalUsername;

    public LdapUser(final String name, String originalUsername, final SearchResultEntry userEntry) {
        super(name);
        this.originalUsername = originalUsername;
        this.userEntry = userEntry;
    }

    public SearchResultEntry getUserEntry() {
        return userEntry;
    }
    
    public String getDn() {
        return userEntry.getDN();
    }

    public String getOriginalUsername() {
        return originalUsername;
    }
}
