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
import org.jboss.as.controller.ObjectListAttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
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
import org.wildfly.security.auth.provider.ldap.AttributeMapping;
import org.wildfly.security.auth.provider.ldap.DirContextFactory;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder.IdentityMappingBuilder;
import org.wildfly.security.auth.provider.ldap.SimpleDirContextFactoryBuilder;
import org.wildfly.security.auth.server.SecurityRealm;

/**
 * A {@link ResourceDefinition} for a {@link SecurityRealm} backed by LDAP.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class LdapRealmDefinition extends SimpleResourceDefinition {

    static final ServiceUtil<SecurityRealm> REALM_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_REALM_RUNTIME_CAPABILITY, ElytronDescriptionConstants.LDAP_REALM, SecurityRealm.class);

    static class AttributeMappingObjectDefinition {
        static final SimpleAttributeDefinition FROM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.FROM, ModelType.STRING, false)
                .setAlternatives(ElytronDescriptionConstants.FILTER)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition TO = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.TO, ModelType.STRING, true)
                .setRequires(ElytronDescriptionConstants.FROM)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition FILTER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.FILTER, ModelType.STRING, true)
                .setRequires(ElytronDescriptionConstants.TO)
                .setAlternatives(ElytronDescriptionConstants.FROM)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition FILTER_BASE_DN = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.FILTER_BASE_DN, ModelType.STRING, true)
                .setRequires(ElytronDescriptionConstants.FILTER)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition AS_RDN = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.AS_RDN, ModelType.STRING, true)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {FROM, TO, FILTER, FILTER_BASE_DN, AS_RDN};

        static final ObjectTypeAttributeDefinition OBJECT_DEFINITION = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.ATTRIBUTE, ATTRIBUTES)
                .setAllowNull(true)
                .build();
    }

    static class IdentityMappingObjectDefinition {

        static final SimpleAttributeDefinition RDN_IDENTIFIER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.RDN_IDENTIFIER, ModelType.STRING, false)
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
                .setRequires(ElytronDescriptionConstants.RDN_IDENTIFIER)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final ObjectListAttributeDefinition ATTRIBUTE_MAPPINGS = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.ATTRIBUTE_MAPPING, AttributeMappingObjectDefinition.OBJECT_DEFINITION)
                .setAllowNull(true)
                .setAttributeGroup(ElytronDescriptionConstants.ATTRIBUTE)
                .setAllowDuplicates(true)
                .build();

        static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] {RDN_IDENTIFIER, USE_RECURSIVE_SEARCH, SEARCH_BASE_DN, ATTRIBUTE_MAPPINGS};

        static final ObjectTypeAttributeDefinition OBJECT_DEFINITION = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.IDENTITY_MAPPING, ATTRIBUTES)
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

    static final SimpleAttributeDefinition DIRECT_VERIFICATION = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.DIRECT_VERIFICATION, ModelType.BOOLEAN, true)
        .setDefaultValue(new ModelNode(false))
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] {DirContextObjectDefinition.OBJECT_DEFINITION, IdentityMappingObjectDefinition.OBJECT_DEFINITION, DIRECT_VERIFICATION};

    private static final AbstractAddStepHandler ADD = new RealmAddHandler();
    private static final OperationStepHandler REMOVE = new SingleCapabilityServiceRemoveHandler<SecurityRealm>(ADD, SECURITY_REALM_RUNTIME_CAPABILITY, SecurityRealm.class);
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

    @Override
    public void registerCapabilities(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerCapability(SECURITY_REALM_RUNTIME_CAPABILITY);
    }

    private static class RealmAddHandler extends BaseAddHandler {

        public static final String CONNECTION_POOLING_PROPERTY = "com.sun.jndi.ldap.connect.pool";

        private RealmAddHandler() {
            super(SECURITY_REALM_RUNTIME_CAPABILITY, ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<Void> runtimeCapability = SECURITY_REALM_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName realmName = runtimeCapability.getCapabilityServiceName(SecurityRealm.class);
            final LdapSecurityRealmBuilder builder = LdapSecurityRealmBuilder.builder();

            configureIdentityMapping(context, model, builder);
            configureDirContext(context, model, builder);

            if (DIRECT_VERIFICATION.resolveModelAttribute(context, model).asBoolean()) {
                builder.addDirectEvidenceVerification();
            }

            TrivialService<SecurityRealm> ldapRealmService = new TrivialService<SecurityRealm>(builder::build);
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

        private void configureIdentityMapping(OperationContext context, ModelNode model, LdapSecurityRealmBuilder builder) throws OperationFailedException {
            ModelNode principalMappingNode = IdentityMappingObjectDefinition.OBJECT_DEFINITION.resolveModelAttribute(context, model);

            IdentityMappingBuilder identityMappingBuilder = builder.identityMapping();

            ModelNode nameAttributeNode = IdentityMappingObjectDefinition.RDN_IDENTIFIER.resolveModelAttribute(context, principalMappingNode);

            identityMappingBuilder.setRdnIdentifier(nameAttributeNode.asString());

            ModelNode searchDnNode = IdentityMappingObjectDefinition.SEARCH_BASE_DN.resolveModelAttribute(context, principalMappingNode);

            if (searchDnNode.isDefined()) {
                identityMappingBuilder.setSearchDn(searchDnNode.asString());
            }

            ModelNode useRecursiveSearchNode = IdentityMappingObjectDefinition.USE_RECURSIVE_SEARCH.resolveModelAttribute(context, principalMappingNode);

            if (useRecursiveSearchNode.asBoolean()) {
                identityMappingBuilder.searchRecursive();
            }

            ModelNode attributeMappingNode = IdentityMappingObjectDefinition.ATTRIBUTE_MAPPINGS.resolveModelAttribute(context, principalMappingNode);

            if (attributeMappingNode.isDefined()) {
                for (ModelNode attributeNode : attributeMappingNode.asList()) {
                    ModelNode fromNode = AttributeMappingObjectDefinition.FROM.resolveModelAttribute(context, attributeNode);
                    ModelNode filterNode = AttributeMappingObjectDefinition.FILTER.resolveModelAttribute(context, attributeNode);
                    ModelNode filterBaseDnNode = AttributeMappingObjectDefinition.FILTER_BASE_DN.resolveModelAttribute(context, attributeNode);
                    AttributeMapping attribute;

                    if (filterBaseDnNode.isDefined()) {
                        attribute = AttributeMapping.fromFilter(filterBaseDnNode.asString(), filterNode.asString(), fromNode.asString());
                    } else if (filterNode.isDefined()) {
                        attribute = AttributeMapping.fromFilter(filterNode.asString(), fromNode.asString());
                    } else {
                        attribute = AttributeMapping.from(fromNode.asString());
                    }

                    ModelNode toNode = AttributeMappingObjectDefinition.TO.resolveModelAttribute(context, attributeNode);

                    if (toNode.isDefined()) {
                        attribute.to(toNode.asString());
                    }

                    ModelNode asRdnNode = AttributeMappingObjectDefinition.AS_RDN.resolveModelAttribute(context, attributeNode);

                    if (asRdnNode.isDefined()) {
                        attribute.asRdn(asRdnNode.asString());
                    }

                    identityMappingBuilder.map(attribute);
                }
            }

            identityMappingBuilder.build();
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler() {
            super(ElytronDescriptionConstants.LDAP_REALM, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress pathAddress) {
            return SECURITY_REALM_RUNTIME_CAPABILITY.fromBaseCapability(pathAddress.getLastElement().getValue()).getCapabilityServiceName(SecurityRealm.class);
        }
    }
}