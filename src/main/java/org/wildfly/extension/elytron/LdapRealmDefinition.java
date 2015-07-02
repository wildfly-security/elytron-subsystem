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

import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;

import java.util.Properties;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.security.auth.provider.ldap.DirContextFactory;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder.PrincipalMappingBuilder;
import org.wildfly.security.auth.provider.ldap.SimpleDirContextFactoryBuilder;
import org.wildfly.security.auth.spi.SecurityRealm;

/**
 * A {@link ResourceDefinition} for a {@link SecurityRealm} backed by LDAP.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class LdapRealmDefinition extends SimpleResourceDefinition {

    static final ServiceUtil<SecurityRealm> REALM_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_REALM_RUNTIME_CAPABILITY, ElytronDescriptionConstants.LDAP_REALM, SecurityRealm.class);

    static class PrincipalMappingObjectDefinition {

        static final SimpleAttributeDefinition NAME_ATTRIBUTE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.NAME_ATTRIBUTE, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition USE_X500_PRINCIPAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.USE_X500_PRINCIPAL, ModelType.BOOLEAN, false)
                .setDefaultValue(new ModelNode(false))
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition USE_RECURSIVE_SEARCH = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.USE_RECURSIVE_SEARCH, ModelType.BOOLEAN, false)
                .setRequires(ElytronDescriptionConstants.SEARCH_BASE_DN)
                .setDefaultValue(new ModelNode(false))
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition SEARCH_BASE_DN = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SEARCH_BASE_DN, ModelType.STRING, true)
                .setRequires(ElytronDescriptionConstants.NAME_ATTRIBUTE)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition CACHE_PRINCIPAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CACHE_PRINCIPAL, ModelType.BOOLEAN, false)
                .setDefaultValue(new ModelNode(false))
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {NAME_ATTRIBUTE, USE_X500_PRINCIPAL, USE_RECURSIVE_SEARCH, SEARCH_BASE_DN, CACHE_PRINCIPAL};

        static final ObjectTypeAttributeDefinition OBJECT_DEFINITION = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.PRINCIPAL_MAPPING, ATTRIBUTES)
                .setAllowNull(false)
                .build();
    }

    static class DirContextObjectDefinition {

        static final SimpleAttributeDefinition URL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.URL, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition AUTHENTICATION_LEVEL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.AUTHENTICATION_LEVEL, ModelType.STRING, false)
                .setDefaultValue(new ModelNode("simple"))
                .setAllowedValues("none", "simple", "strong")
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition PRINCIPAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PRINCIPAL, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition CREDENTIAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CREDENTIAL, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition ENABLE_CONNECTION_POOLING = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ENABLE_CONNECTION_POOLING, ModelType.BOOLEAN, false)
                .setDefaultValue(new ModelNode(false))
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {URL, AUTHENTICATION_LEVEL, PRINCIPAL, CREDENTIAL, ENABLE_CONNECTION_POOLING};

        static final ObjectTypeAttributeDefinition OBJECT_DEFINITION = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.DIR_CONTEXT, ATTRIBUTES)
                .setAllowNull(false)
                .build();
    }

    private static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {DirContextObjectDefinition.OBJECT_DEFINITION, PrincipalMappingObjectDefinition.OBJECT_DEFINITION};

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

        public static final String CONNECTION_POOLING_PROPERTY = "com.sun.jndi.ldap.connect.pool";

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

            LdapRealmService ldapRealmService = new LdapRealmService(builder);
            ServiceBuilder<SecurityRealm> serviceBuilder = serviceTarget.addService(realmName, ldapRealmService);

            commonDependencies(serviceBuilder).setInitialMode(ServiceController.Mode.ACTIVE).install();
        }

        private void configureDirContext(OperationContext context, ModelNode model, LdapSecurityRealmBuilder builder) throws OperationFailedException {
            ModelNode dirContextNode = DirContextObjectDefinition.OBJECT_DEFINITION.resolveModelAttribute(context, model);

            Properties connectionProperties = new Properties();

            ModelNode enableConnectionPoolingNode = DirContextObjectDefinition.ENABLE_CONNECTION_POOLING.resolveModelAttribute(context, dirContextNode);

            connectionProperties.put(CONNECTION_POOLING_PROPERTY, enableConnectionPoolingNode.asBoolean());

            DirContextFactory dirContextFactory = SimpleDirContextFactoryBuilder.builder()
                    .setProviderUrl(DirContextObjectDefinition.URL.resolveModelAttribute(context, dirContextNode).asString())
                    .setSecurityAuthentication(DirContextObjectDefinition.AUTHENTICATION_LEVEL.resolveModelAttribute(context, dirContextNode).asString())
                    .setSecurityPrincipal(DirContextObjectDefinition.PRINCIPAL.resolveModelAttribute(context, dirContextNode).asString())
                    .setSecurityCredential(DirContextObjectDefinition.CREDENTIAL.resolveModelAttribute(context, dirContextNode).asString())
                    .setConnectionProperties(connectionProperties)
                    .build();

            builder.setDirContextFactory(dirContextFactory);
        }

        private void configurePrincipalMapping(OperationContext context, ModelNode model, LdapSecurityRealmBuilder builder) throws OperationFailedException {
            ModelNode principalMappingNode = PrincipalMappingObjectDefinition.OBJECT_DEFINITION.resolveModelAttribute(context, model);

            PrincipalMappingBuilder principalMappingBuilder = PrincipalMappingBuilder.builder();

            ModelNode nameAttributeNode = PrincipalMappingObjectDefinition.NAME_ATTRIBUTE.resolveModelAttribute(context, principalMappingNode);

            principalMappingBuilder.setNameAttribute(nameAttributeNode.asString());

            ModelNode usex500PrincipalNode = PrincipalMappingObjectDefinition.USE_X500_PRINCIPAL.resolveModelAttribute(context, principalMappingNode);

            if (usex500PrincipalNode.asBoolean()) {
                principalMappingBuilder.useX500Principal();
            }

            ModelNode searchDnNode = PrincipalMappingObjectDefinition.SEARCH_BASE_DN.resolveModelAttribute(context, principalMappingNode);

            if (searchDnNode.isDefined()) {
                principalMappingBuilder.setSearchDn(searchDnNode.asString());
            }

            ModelNode useRecursiveSearchNode = PrincipalMappingObjectDefinition.USE_RECURSIVE_SEARCH.resolveModelAttribute(context, principalMappingNode);

            if (useRecursiveSearchNode.asBoolean()) {
                principalMappingBuilder.searchRecursive();
            }

            ModelNode cachePrincipalNode = PrincipalMappingObjectDefinition.CACHE_PRINCIPAL.resolveModelAttribute(context, principalMappingNode);

            if (cachePrincipalNode.asBoolean()) {
                principalMappingBuilder.cachePrincipal();
            }

            builder.principalMapping(principalMappingBuilder.build());
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