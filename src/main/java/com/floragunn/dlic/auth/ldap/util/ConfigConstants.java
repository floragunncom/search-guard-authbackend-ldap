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

public final class ConfigConstants {

    public static final String LDAP_AUTHC_USERBASE = "userbase";
    public static final String LDAP_AUTHC_USERNAME_ATTRIBUTE = "username_attribute";
    public static final String LDAP_AUTHC_USERSEARCH = "usersearch";
    
    public static final String LDAP_AUTHZ_RESOLVE_NESTED_ROLES = "resolve_nested_roles";
    public static final String LDAP_AUTHZ_ROLEBASE = "rolebase";
    public static final String LDAP_AUTHZ_ROLENAME = "rolename";
    public static final String LDAP_AUTHZ_ROLESEARCH = "rolesearch";
    public static final String LDAP_AUTHZ_USERROLEATTRIBUTE = "userroleattribute";
    public static final String LDAP_AUTHZ_USERROLENAME = "userrolename";
    public static final String LDAP_AUTHZ_SKIP_USERS = "skip_users";
    
    public static final String LDAP_HOSTS = "hosts";
    public static final String LDAP_BIND_DN = "bind_dn";
    public static final String LDAP_PASSWORD = "password";
    public static final String LDAP_FAKE_LOGIN_ENABLED = "fakelogin_enabled";
    public static final String LDAP_FAKE_LOGIN_DN = "fakelogin_dn";
    public static final String LDAP_FAKE_LOGIN_Password = "fakelogin_password";
    
    public static final String LDAPS_VERIFY_HOSTNAMES = "verify_hostnames";
    public static final String LDAPS_ENABLE_SSL = "enable_ssl";
    public static final String LDAPS_ENABLE_START_TLS = "enable_start_tls";
    public static final String LDAPS_ENABLE_SSL_CLIENT_AUTH = "enable_ssl_client_auth";

    private ConfigConstants() {

    }

}
