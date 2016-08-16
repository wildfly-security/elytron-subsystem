/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2016 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.extension.elytron;

import static org.wildfly.security.auth.server.IdentityLocator.fromName;

import java.security.spec.KeySpec;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.msc.service.ServiceName;
import org.junit.Assert;
import org.junit.Test;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.OneTimePasswordSpec;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class RealmsTestCase extends AbstractSubsystemTest {

    public RealmsTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    /* Test properties-realm */
    @Test
    public void testPropertyRealm() throws Exception {
        KernelServices services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource("realms-test.xml").build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }

        ServiceName serviceName = Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY.getCapabilityServiceName("TestingPropertyRealm1");
        SecurityRealm securityRealm = (SecurityRealm) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(securityRealm);

        RealmIdentity identity1 = securityRealm.getRealmIdentity(fromName("user1"));
        Assert.assertTrue(identity1.exists());
        Assert.assertTrue(identity1.verifyEvidence(new PasswordGuessEvidence("password1".toCharArray())));
        Assert.assertFalse(identity1.verifyEvidence(new PasswordGuessEvidence("password2".toCharArray())));
        identity1.dispose();

        RealmIdentity identity2 = securityRealm.getRealmIdentity(fromName("user2"));
        Assert.assertTrue(identity2.exists());
        Assert.assertTrue(identity2.verifyEvidence(new PasswordGuessEvidence("password2".toCharArray())));
        identity2.dispose();

        RealmIdentity identity9 = securityRealm.getRealmIdentity(fromName("user9"));
        Assert.assertFalse(identity9.exists());
        Assert.assertFalse(identity9.verifyEvidence(new PasswordGuessEvidence("password9".toCharArray())));
        identity9.dispose();
    }

    /* Test filesystem-realm with existing filesystem from resources, without relative-to */
    @Test
    public void testFilesystemRealm() throws Exception {
        KernelServices services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource("realms-test.xml").build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }

        ServiceName serviceName = Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY.getCapabilityServiceName("FilesystemRealm");
        ModifiableSecurityRealm securityRealm = (ModifiableSecurityRealm) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(securityRealm);

        RealmIdentity identity1 = securityRealm.getRealmIdentity(fromName("firstUser"));
        Assert.assertTrue(identity1.exists());
        identity1.dispose();

        testModifiability(securityRealm);
    }

    @Test
    public void testLdapRealm() throws Exception {
        TestEnvironment.startLdapService();
        KernelServices services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource("realms-test.xml").build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }

        // test DirContext first
        ServiceName serviceNameDirContext = Capabilities.DIR_CONTEXT_RUNTIME_CAPABILITY.getCapabilityServiceName("ldap1");
        ExceptionSupplier<DirContext, NamingException> dirContextSup = (ExceptionSupplier<DirContext, NamingException>) services.getContainer().getService(serviceNameDirContext).getValue();
        DirContext dirContext = dirContextSup.get();
        Assert.assertNotNull(dirContext);
        Assert.assertEquals("org.wildfly.security.auth.realm.ldap.DelegatingLdapContext", dirContext.getClass().getName());
        dirContext.close();

        // test LdapRealm
        ServiceName serviceName = Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY.getCapabilityServiceName("LdapRealm");
        ModifiableSecurityRealm securityRealm = (ModifiableSecurityRealm) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(securityRealm);

        RealmIdentity identity1 = securityRealm.getRealmIdentity(fromName("plainUser"));
        Assert.assertTrue(identity1.exists());
        identity1.dispose();

        testModifiability(securityRealm);
    }

    private void testModifiability(ModifiableSecurityRealm securityRealm) throws Exception {
        // obtain original count of identities
        int oldCount = getRealmIdentityCount(securityRealm);
        Assert.assertTrue(oldCount > 0);

        // create identity
        ModifiableRealmIdentity identity1 = securityRealm.getRealmIdentityForUpdate(fromName("createdUser"));
        Assert.assertFalse(identity1.exists());
        identity1.create();
        Assert.assertTrue(identity1.exists());

        // write password credential
        List<Credential> credentials = new LinkedList<>();
        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        KeySpec spec = new ClearPasswordSpec("createdPassword".toCharArray());
        credentials.add(new PasswordCredential(factory.generatePassword(spec)));

        PasswordFactory factoryOtp = PasswordFactory.getInstance(OneTimePassword.ALGORITHM_OTP_SHA1);
        KeySpec specOtp = new OneTimePasswordSpec(new byte[]{0x12}, new byte[]{0x34}, 56789);
        credentials.add(new PasswordCredential(factoryOtp.generatePassword(specOtp)));

        identity1.setCredentials(credentials);
        identity1.dispose();

        // read created identity
        ModifiableRealmIdentity identity2 = securityRealm.getRealmIdentityForUpdate(fromName("createdUser"));
        Assert.assertTrue(identity2.exists());

        // verify password
        Assert.assertTrue(identity2.verifyEvidence(new PasswordGuessEvidence("createdPassword".toCharArray())));

        // obtain OTP
        OneTimePassword otp = identity2.getCredential(PasswordCredential.class, OneTimePassword.ALGORITHM_OTP_SHA1).getPassword(OneTimePassword.class);
        Assert.assertArrayEquals(new byte[]{0x12}, otp.getHash());
        Assert.assertArrayEquals(new byte[]{0x34}, otp.getSeed());
        Assert.assertEquals(56789, otp.getSequenceNumber());
        identity2.dispose();

        // iterate (include created identity)
        int newCount = getRealmIdentityCount(securityRealm);
        Assert.assertEquals(oldCount + 1, newCount);

        // delete identity
        identity1 = securityRealm.getRealmIdentityForUpdate(fromName("createdUser"));
        identity1.delete();
        Assert.assertFalse(identity1.exists());
        identity1.dispose();
    }

    private int getRealmIdentityCount(final ModifiableSecurityRealm securityRealm) throws Exception {
        int count = 0;
        Iterator<ModifiableRealmIdentity> it = securityRealm.getRealmIdentityIterator();
        while (it.hasNext()) {
            ModifiableRealmIdentity identity = it.next();
            Assert.assertTrue(identity.exists());
            identity.dispose();
            count++;
        }
        return count;
    }

}
