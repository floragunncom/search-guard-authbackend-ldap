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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.ldaptive.LdapEntry;

import com.floragunn.searchguard.user.User;

public class LdapUser extends User {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    private final LdapEntry userEntry;
    private final Set<LdapEntry> roleEntries = new HashSet<>();

    public LdapUser(final String name, final LdapEntry userEntry) {
        super(name);
        this.userEntry = userEntry;
    }

    public void addRoleEntry(final LdapEntry entry) {
        roleEntries.add(entry);
    }

    public void addRoleEntries(final Collection<LdapEntry> entries) {
        roleEntries.addAll(entries);
    }

    public LdapEntry getUserEntry() {
        return userEntry;
    }

    public Set<LdapEntry> getRoleEntries() {
        return Collections.unmodifiableSet(roleEntries);
    }

    @Override
    public void copyRolesFrom(final User user) {
        this.addRoleEntries(((LdapUser) user).getRoleEntries());
        super.copyRolesFrom(user);
    }
}
