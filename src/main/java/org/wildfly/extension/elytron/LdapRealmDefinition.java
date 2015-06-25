/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.extension.elytron.LdapAttributeDefinitions.DirContextAttributes;
import org.wildfly.extension.elytron.LdapAttributeDefinitions.PrincipalMappingAttributes;
import org.wildfly.security.auth.provider.ldap.DirContextFactory;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.provider.ldap.SimpleDirContextFactoryBuilder;
import org.wildfly.security.auth.spi.CredentialSupport;
import org.wildfly.security.auth.spi.SecurityRealm;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;

import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;

/**
 * A {@link ResourceDefinition} for a {@link SecurityRealm} backed by LDAP.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class LdapRealmDefinition extends SimpleResourceDefinition {

    static final ServiceUtil<SecurityRealm> REALM_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_REALM_RUNTIME_CAPABILITY, ElytronDescriptionConstants.LDAP_REALM, SecurityRealm.class);

    private static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {DirContextAttributes.DIR_CONTEXT, PrincipalMappingAttributes.PRINCIPAL_MAPPING};

    private static final AbstractAddStepHandler ADD = new RealmAddHandler();
    private static final OperationStepHandler REMOVE = new RealmRemoveHandler(ADD);
    private static final OperationStepHandler WRITE = new WriteAttributeHandler();

    LdapRealmDefinition() {
        super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.LDAP_REALM), ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.LDAP_REALM))
            .setAddHandler(ADD)
            .setRemoveHandler(REMOVE)
            .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
            .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition current : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(current, null, WRITE);
        }
    }

    private static class RealmAddHandler extends AbstractAddStepHandler {

        private RealmAddHandler() {
            super(SECURITY_REALM_RUNTIME_CAPABILITY, ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<Void> runtimeCapability = RuntimeCapability.fromBaseCapability(SECURITY_REALM_RUNTIME_CAPABILITY, context.getCurrentAddressValue());
            ServiceName realmName = runtimeCapability.getCapabilityServiceName(SecurityRealm.class);
            LdapSecurityRealmBuilder builder = LdapSecurityRealmBuilder.builder();

            configurePrincipalMapping(context, model, builder);
            configureDirContext(context, model, builder);
            configureCredentialSupport(builder);

            LdapRealmService ldapRealmService = new LdapRealmService(builder);
            ServiceBuilder<SecurityRealm> serviceBuilder = serviceTarget.addService(realmName, ldapRealmService);

            commonDependencies(serviceBuilder).setInitialMode(ServiceController.Mode.ACTIVE).install();
        }

        private void configureDirContext(OperationContext context, ModelNode model, LdapSecurityRealmBuilder builder) throws OperationFailedException {
            ModelNode dirContextNode = DirContextAttributes.DIR_CONTEXT.resolveModelAttribute(context, model);

            DirContextFactory dirContextFactory = SimpleDirContextFactoryBuilder.builder()
                    .setProviderUrl(DirContextAttributes.URL.resolveModelAttribute(context, dirContextNode).asString())
                    .setSecurityAuthentication(DirContextAttributes.AUTHENTICATION_LEVEL.resolveModelAttribute(context, dirContextNode).asString())
                    .setSecurityPrincipal(DirContextAttributes.PRINCIPAL.resolveModelAttribute(context, dirContextNode).asString())
                    .setSecurityCredential(DirContextAttributes.CREDENTIAL.resolveModelAttribute(context, dirContextNode).asString())
                    .build();

            builder.setDirContextFactory(dirContextFactory);
        }

        private void configurePrincipalMapping(OperationContext context, ModelNode model, LdapSecurityRealmBuilder builder) throws OperationFailedException {
            ModelNode principalMappingNode = PrincipalMappingAttributes.PRINCIPAL_MAPPING.resolveModelAttribute(context, model);

            builder.principalMapping()
                .setNameAttribute(PrincipalMappingAttributes.NAME_ATTRIBUTE.resolveModelAttribute(context, principalMappingNode).asString())
                .setNameIsDn(PrincipalMappingAttributes.USE_X500_NAME.resolveModelAttribute(context, principalMappingNode).asBoolean())
                .setPrincipalUseDn(PrincipalMappingAttributes.USE_X500_PRINCIPAL.resolveModelAttribute(context, principalMappingNode).asBoolean())
                .setRecursive(PrincipalMappingAttributes.USE_RECURSIVE_SEARCH.resolveModelAttribute(context, principalMappingNode).asBoolean())
                .setReloadPrincipalName(PrincipalMappingAttributes.CACHE_PRINCIPAL.resolveModelAttribute(context, principalMappingNode).asBoolean())
                .setSearchDn(PrincipalMappingAttributes.SEARCH_BASE_DN.resolveModelAttribute(context, principalMappingNode).asString())
                .build();
        }

        private void configureCredentialSupport(LdapSecurityRealmBuilder builder) {
            // for now, we support all available credential types. In the future we may want to provide a specific configuration to enable/disable this.
            builder.userPassword()
                    .addCredentialSupport(ClearPassword.class, CredentialSupport.UNKNOWN)
                    .addCredentialSupport(SimpleDigestPassword.class, CredentialSupport.UNKNOWN)
                    .addCredentialSupport(SaltedSimpleDigestPassword.class, CredentialSupport.UNKNOWN)
                    .addCredentialSupport(BSDUnixDESCryptPassword.class, CredentialSupport.UNKNOWN)
                    .addCredentialSupport(UnixDESCryptPassword.class, CredentialSupport.UNKNOWN)
                    .build();
        }
    }

    private static class RealmRemoveHandler extends ServiceRemoveStepHandler {

        public RealmRemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation, SECURITY_REALM_RUNTIME_CAPABILITY);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return REALM_SERVICE_UTIL.serviceName(name);
        }
    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler() {
            super(ElytronDescriptionConstants.LDAP_REALM, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress arg0) {
            return null;
        }
    }
}