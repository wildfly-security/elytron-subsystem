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

import mockit.integration.junit4.JMockit;
import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.msc.service.ServiceName;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.permission.PermissionVerifier;

import javax.security.auth.x500.X500Principal;
import java.io.FilePermission;
import java.security.Principal;


/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class DomainTestCase extends AbstractSubsystemTest {

    public DomainTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    private KernelServices services = null;

    private void init() throws Exception {
        TestEnvironment.mockCallerModuleClassloader();
        services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource("domain-test.xml").build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }
    }

    @Test
    public void testDefaultRealmIdentity() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("MyDomain");
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        ServerAuthenticationContext context = domain.createNewAuthenticationContext();
        context.setAuthenticationName("firstUser"); // from FileRealm
        Assert.assertTrue(context.exists());
        context.succeed();
        SecurityIdentity identity = context.getAuthorizedIdentity();
        Assert.assertEquals("John", identity.getAttributes().get("firstName").get(0));
        Assert.assertEquals("Smith", identity.getAttributes().get("lastName").get(0));

        Roles roles = identity.getRoles();
        Assert.assertTrue(roles.contains("prefixEmployeesuffix"));
        Assert.assertTrue(roles.contains("prefixManagersuffix"));
        Assert.assertTrue(roles.contains("prefixAdminsuffix"));
        Assert.assertEquals("firstUser", identity.getPrincipal().getName());

        Assert.assertTrue(identity.implies(new FilePermission("test", "read")));
        Assert.assertFalse(identity.implies(new FilePermission("test", "write")));
    }

    @Test
    public void testNonDefaultRealmIdentity() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("MyDomain");
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        MechanismConfiguration mechConf = MechanismConfiguration.builder()
                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("FileRealm").build())
                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("PropRealm").build())
                .build();
        ServerAuthenticationContext context = domain.createNewAuthenticationContext(mechConf);

        context.setMechanismRealmName("PropRealm");
        context.setAuthenticationName("xser1@PropRealm");
        Assert.assertTrue(context.exists());
        context.succeed();
        SecurityIdentity identity = context.getAuthorizedIdentity();
        Assert.assertEquals("yser1@PropRealm", identity.getPrincipal().getName()); // after pre-realm-name-rewriter only
    }

    @Test
    public void testNamePrincipalMapping() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("MyDomain");
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        Assert.assertFalse(domain.mapName("wrong").exists());
        Assert.assertFalse(domain.mapName("firstUser@wrongRealm").exists());
        Assert.assertTrue(domain.mapName("firstUser").exists());
        Assert.assertTrue(domain.mapName("user1@PropRealm").exists());
        Assert.assertTrue(domain.mapPrincipal(new NamePrincipal("user1@PropRealm")).exists());
    }

    @Test
    public void testX500PrincipalMapping() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("X500Domain");
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        Assert.assertTrue(domain.mapPrincipal(new X500Principal("cn=firstUser,ou=group")).exists());

    }

    @Test
    public void testTrustedSecurityDomains() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("MyDomain");
        SecurityDomain myDomain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(myDomain);

        serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("X500Domain");
        SecurityDomain x500Domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(x500Domain);

        serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("AnotherDomain");
        SecurityDomain anotherDomain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(anotherDomain);

        SecurityIdentity establishedIdentity = getIdentityFromDomain(myDomain, "firstUser");
        ServerAuthenticationContext authenticationContext = anotherDomain.createNewAuthenticationContext();

        // AnotherDomain trusts MyDomain
        Assert.assertTrue(authenticationContext.importIdentity(establishedIdentity));

        establishedIdentity = getIdentityFromDomain(anotherDomain, "firstUser");
        authenticationContext = x500Domain.createNewAuthenticationContext();
        // X500Domain does not trust AnotherDomain
        Assert.assertFalse(authenticationContext.importIdentity(establishedIdentity));
    }

    public static class MyPermissionMapper implements PermissionMapper {
        @Override
        public PermissionVerifier mapPermissions(Principal principal, Roles roles) {
            return permission -> roles.contains("prefixAdminsuffix") && permission.getActions().equals("read");
        }
    }

    public static class LoginPermissionMapper implements PermissionMapper {
        @Override
        public PermissionVerifier mapPermissions(Principal principal, Roles roles) {
            return PermissionVerifier.from(new LoginPermission());
        }
    }

    private SecurityIdentity getIdentityFromDomain(final SecurityDomain securityDomain, final String userName) throws Exception {
        final ServerAuthenticationContext authenticationContext = securityDomain.createNewAuthenticationContext();
        authenticationContext.setAuthenticationName(userName);
        authenticationContext.authorize();
        authenticationContext.succeed();
        return authenticationContext.getAuthorizedIdentity();
    }
}
