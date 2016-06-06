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

package com.floragunn.dlic.auth.ldap.srv;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import org.apache.commons.io.IOUtils;
import org.apache.directory.api.ldap.model.constants.SupportedSaslMechanisms;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.annotations.SaslMechanism;
import org.apache.directory.server.core.annotations.AnnotationUtils;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.factory.DSAnnotationProcessor;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.factory.ServerAnnotationProcessor;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.ldap.handlers.sasl.cramMD5.CramMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.digestMD5.DigestMd5MechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.gssapi.GssapiMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.ntlm.NtlmMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.plain.PlainMechanismHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.floragunn.dlic.auth.ldap.LdapBackendTest;

public class EmbeddedLDAPServer {

    private final Logger log = LoggerFactory.getLogger(EmbeddedLDAPServer.class);

    private DirectoryService directoryService;
    private LdapServer ldapServer;
    // private KdcServer kdcServer;
    public final static int ldapPort = 40622;
    public final static int ldapsPort = 40623;
    // private final static int kdcPort = 40624;

    private SchemaManager schemaManager;

    public static void main(final String[] args) throws Exception {
        new EmbeddedLDAPServer().start();
    }

    /*public void createKeytab(final String principalName, final String passPhrase, final File keytabFile) throws IOException {
        final KerberosTime timeStamp = new KerberosTime();
        final int principalType = 1; // KRB5_NT_PRINCIPAL

        final Keytab keytab = keytabFile.exists() ? Keytab.read(keytabFile) : Keytab.getInstance();

        final List<KeytabEntry> entries = new ArrayList<KeytabEntry>();
        for (final Map.Entry<EncryptionType, EncryptionKey> keyEntry : KerberosKeyFactory.getKerberosKeys(principalName, passPhrase)
                .entrySet()) {
            final EncryptionKey key = keyEntry.getValue();
            final byte keyVersion = (byte) key.getKeyVersion();
            entries.add(new KeytabEntry(principalName, principalType, timeStamp, keyVersion, key));
        }

        entries.addAll(keytab.getEntries());

        keytab.setEntries(entries);
        keytab.write(keytabFile);
        log.debug("Keytab with " + keytab.getEntries().size() + " entries written to " + keytabFile.getAbsolutePath());
    }*/

    @CreateDS(name = "ExampleComDS", allowAnonAccess = true, partitions = { @CreatePartition(name = "examplecom", suffix = "o=TEST", contextEntry = @ContextEntry(entryLdif = "dn: o=TEST\n"
            + "dc: TEST\n" + "objectClass: top\n" + "objectClass: domain\n\n"), indexes = { @CreateIndex(attribute = "objectClass"),
        @CreateIndex(attribute = "dc"), @CreateIndex(attribute = "ou") }) }, additionalInterceptors = { KeyDerivationInterceptor.class })
    @CreateLdapServer(allowAnonymousAccess = true, transports = {
            @CreateTransport(protocol = "LDAP", address = "localhost", port = ldapPort),
            @CreateTransport(protocol = "LDAPS", address = "localhost", port = ldapsPort) },

            saslHost = "localhost", saslPrincipal = "ldap/localhost@EXAMPLE.COM", saslMechanisms = {
            @SaslMechanism(name = SupportedSaslMechanisms.PLAIN, implClass = PlainMechanismHandler.class),
            @SaslMechanism(name = SupportedSaslMechanisms.CRAM_MD5, implClass = CramMd5MechanismHandler.class),
            @SaslMechanism(name = SupportedSaslMechanisms.DIGEST_MD5, implClass = DigestMd5MechanismHandler.class),
            @SaslMechanism(name = SupportedSaslMechanisms.GSSAPI, implClass = GssapiMechanismHandler.class),
            @SaslMechanism(name = SupportedSaslMechanisms.NTLM, implClass = NtlmMechanismHandler.class),
            @SaslMechanism(name = SupportedSaslMechanisms.GSS_SPNEGO, implClass = NtlmMechanismHandler.class) }, extendedOpHandlers = { StartTlsHandler.class }

            )
    // @CreateKdcServer(primaryRealm = "example.com", kdcPrincipal =
    // "krbtgt/example.com@example.com", searchBaseDn = "o=TEST",
    // maxTicketLifetime = 1000,
    // maxRenewableLifetime = 2000,
    // transports = { @CreateTransport(protocol = "TCP", port = kdcPort),
    // @CreateTransport(protocol = "UDP", port = kdcPort) })
    public void start() throws Exception {

        directoryService = DSAnnotationProcessor.getDirectoryService();
        // kdcServer = ServerAnnotationProcessor.getKdcServer(directoryService,
        // kdcPort);
        // kdcServer.getConfig().setPaEncTimestampRequired(false);
        schemaManager = directoryService.getSchemaManager();
        final CreateLdapServer cl = (CreateLdapServer) AnnotationUtils.getInstance(CreateLdapServer.class);
        ldapServer = ServerAnnotationProcessor.instantiateLdapServer(cl, directoryService);

        ldapServer.setKeystoreFile(LdapBackendTest.getAbsoluteFilePathFromClassPath("node-0-keystore.jks").getAbsolutePath());
        ldapServer.setCertificatePassword("changeit");
        
        // ldapServer.setEnabledCipherSuites(Arrays.asList(SecurityUtil.ENABLED_SSL_CIPHERS));

        if (ldapServer.isStarted()) {
            throw new IllegalStateException("Service already running");
        }

        ldapServer.start();

        log.debug("LDAP started");
    }

    public void stop() throws Exception {

        if (!ldapServer.isStarted()) {
            throw new IllegalStateException("Service is not running");
        }

        // kdcServer.stop();
        directoryService.shutdown();
        ldapServer.stop();

        log.debug("LDAP stopped");

    }

    protected final String loadFile(final String file) throws IOException {
        final StringWriter sw = new StringWriter();
        IOUtils.copy(this.getClass().getResourceAsStream("/" + file), sw);
        return sw.toString();
    }

    public int applyLdif(final String ldifFile) throws Exception {

        String ldif = loadFile(ldifFile);
        ldif = ldif.replace("${hostname}", "localhost");
        ldif = ldif.replace("${port}", String.valueOf(ldapPort));

        int i = 0;
        for (final LdifEntry ldifEntry : new LdifReader(new StringReader(ldif))) {
            directoryService.getAdminSession().add(new DefaultEntry(schemaManager, ldifEntry.getEntry()));
            log.trace(ldifEntry.toString());
            i++;
        }

        return i;
    }
}