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

import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.msc.service.ServiceName;
import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import java.security.spec.KeySpec;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

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

        RealmIdentity identity1 = securityRealm.getRealmIdentity("user1", null, null);
        Assert.assertTrue(identity1.exists());
        Assert.assertTrue(identity1.verifyEvidence(new PasswordGuessEvidence("password1".toCharArray())));
        Assert.assertFalse(identity1.verifyEvidence(new PasswordGuessEvidence("password2".toCharArray())));

        RealmIdentity identity2 = securityRealm.getRealmIdentity("user2", null, null);
        Assert.assertTrue(identity2.exists());
        Assert.assertTrue(identity2.verifyEvidence(new PasswordGuessEvidence("password2".toCharArray())));

        RealmIdentity identity9 = securityRealm.getRealmIdentity("user9", null, null);
        Assert.assertFalse(identity9.exists());
        Assert.assertFalse(identity9.verifyEvidence(new PasswordGuessEvidence("password9".toCharArray())));
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

        RealmIdentity identity1 = securityRealm.getRealmIdentity("firstUser", null, null);
        Assert.assertTrue(identity1.exists());

        testModifiability(securityRealm, 3);
    }

    private void testModifiability(ModifiableSecurityRealm securityRealm, int expectedCount) throws Exception {
        // create identity
        ModifiableRealmIdentity identity1 = securityRealm.getRealmIdentityForUpdate("createdUser", null, null);
        Assert.assertFalse(identity1.exists());
        identity1.create();
        Assert.assertTrue(identity1.exists());
        List<Credential> creds = new LinkedList<>();
        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        KeySpec spec = new ClearPasswordSpec("createdPassword".toCharArray());
        creds.add(new PasswordCredential(factory.generatePassword(spec)));
        identity1.setCredentials(creds);

        // read created identity
        ModifiableRealmIdentity identity2 = securityRealm.getRealmIdentityForUpdate("createdUser", null, null);
        Assert.assertTrue(identity2.exists());
        Assert.assertTrue(identity2.verifyEvidence(new PasswordGuessEvidence("createdPassword".toCharArray())));

        // iterate (include created identity)
        int count = 0;
        Iterator<ModifiableRealmIdentity> it = securityRealm.getRealmIdentityIterator();
        while (it.hasNext()) {
            ModifiableRealmIdentity identity = it.next();
            Assert.assertTrue(identity.exists());
            count++;
        }
        Assert.assertEquals(expectedCount, count);

        // delete identity
        identity1.delete();
        Assert.assertFalse(identity1.exists());
    }

}
