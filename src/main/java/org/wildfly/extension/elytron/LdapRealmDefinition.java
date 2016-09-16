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
import org.jboss.as.controller.StringListAttributeDefinition;
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
import org.jboss.msc.value.InjectedValue;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.auth.realm.ldap.AttributeMapping;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder.IdentityMappingBuilder;
import org.wildfly.security.auth.server.SecurityRealm;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapName;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import static org.wildfly.extension.elytron.Capabilities.DIR_CONTEXT_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.IDENTITY_MAPPING;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.OTP_CREDENTIAL_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.USER_PASSWORD_MAPPER;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;

/**
 * A {@link ResourceDefinition} for a {@link SecurityRealm} backed by LDAP.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class LdapRealmDefinition extends SimpleResourceDefinition {

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
                .build();
    }

    interface CredentialMappingObjectDefinition {
        ObjectTypeAttributeDefinition getObjectDefinition();
        SimpleAttributeDefinition[] getAttributes();
        void configure(LdapSecurityRealmBuilder builder, ModelNode node);
    }

    static class UserPasswordCredentialMappingObjectDefinition implements CredentialMappingObjectDefinition {

        static final SimpleAttributeDefinition FROM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.FROM, ModelType.STRING, true)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition WRITABLE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.WRITABLE, ModelType.BOOLEAN, false)
                .setDefaultValue(new ModelNode(false))
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition VERIFIABLE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.VERIFIABLE, ModelType.BOOLEAN, false)
                .setDefaultValue(new ModelNode(true))
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {FROM, WRITABLE, VERIFIABLE};

        static final ObjectTypeAttributeDefinition OBJECT_DEFINITION = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.USER_PASSWORD_MAPPER, ATTRIBUTES)
                .build();

        @Override
        public ObjectTypeAttributeDefinition getObjectDefinition() {
            return OBJECT_DEFINITION;
        }

        @Override
        public SimpleAttributeDefinition[] getAttributes() { // TODO AttributeDefinition ?
            return ATTRIBUTES;
        }

        @Override
        public void configure(LdapSecurityRealmBuilder builder, ModelNode node) {
            String from = node.get(ElytronDescriptionConstants.FROM).asString();
            boolean writable = node.get(ElytronDescriptionConstants.WRITABLE).asBoolean();
            boolean verifiable = node.get(ElytronDescriptionConstants.VERIFIABLE).asBoolean();

            LdapSecurityRealmBuilder.UserPasswordCredentialLoaderBuilder b = builder.userPasswordCredentialLoader();
            if (from != null) b.setUserPasswordAttribute(from);
            if (writable) b.enablePersistence();
            if (!verifiable) b.disableVerification();
            b.build();
        }
    }

    static class OtpCredentialMappingObjectDefinition implements CredentialMappingObjectDefinition {

        static final SimpleAttributeDefinition ALGORITHM_FROM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ALGORITHM_FROM, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition HASH_FROM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.HASH_FROM, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition SEED_FROM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SEED_FROM, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition SEQUENCE_FROM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SEQUENCE_FROM, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {ALGORITHM_FROM, HASH_FROM, SEED_FROM, SEQUENCE_FROM};

        static final ObjectTypeAttributeDefinition OBJECT_DEFINITION = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.OTP_CREDENTIAL_MAPPER, ATTRIBUTES)
                .build();

        @Override
        public ObjectTypeAttributeDefinition getObjectDefinition() {
            return OBJECT_DEFINITION;
        }

        @Override
        public SimpleAttributeDefinition[] getAttributes() {
            return ATTRIBUTES;
        }

        @Override
        public void configure(LdapSecurityRealmBuilder builder, ModelNode node) {
            String algorithmFrom = node.get(ElytronDescriptionConstants.ALGORITHM_FROM).asString();
            String hashFrom = node.get(ElytronDescriptionConstants.HASH_FROM).asString();
            String seedFrom = node.get(ElytronDescriptionConstants.SEED_FROM).asString();
            String sequenceFrom = node.get(ElytronDescriptionConstants.SEQUENCE_FROM).asString();

            LdapSecurityRealmBuilder.OtpCredentialLoaderBuilder b = builder.otpCredentialLoader();
            if (algorithmFrom != null) b.setOtpAlgorithmAttribute(algorithmFrom);
            if (hashFrom != null) b.setOtpHashAttribute(hashFrom);
            if (seedFrom != null) b.setOtpSeedAttribute(seedFrom);
            if (sequenceFrom != null) b.setOtpSequenceAttribute(sequenceFrom);
            b.build();
        }
    }

    static Map<String, CredentialMappingObjectDefinition> SUPPORTED_CREDENTIAL_MAPPERS;

    static {
        Map<String, CredentialMappingObjectDefinition> supported = new HashMap<>();

        supported.put(USER_PASSWORD_MAPPER, new UserPasswordCredentialMappingObjectDefinition());
        supported.put(OTP_CREDENTIAL_MAPPER, new OtpCredentialMappingObjectDefinition());

        SUPPORTED_CREDENTIAL_MAPPERS = Collections.unmodifiableMap(supported);
    }

    static class NewIdentityAttributeObjectDefinition {
        static final SimpleAttributeDefinition NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.NAME, ModelType.STRING, true)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final StringListAttributeDefinition VALUE = new StringListAttributeDefinition.Builder(ElytronDescriptionConstants.VALUE)
                .setAllowExpression(true)
                .setMinSize(1)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] {NAME, VALUE};

        static final ObjectTypeAttributeDefinition OBJECT_DEFINITION = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.ATTRIBUTE, ATTRIBUTES)
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

        static final ObjectListAttributeDefinition NEW_IDENTITY_ATTRIBUTES = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.NEW_IDENTITY_ATTRIBUTES, NewIdentityAttributeObjectDefinition.OBJECT_DEFINITION)
                .setAllowNull(true)
                .setAllowDuplicates(true)
                .build();

        static final SimpleAttributeDefinition ITERATOR_FILTER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ITERATOR_FILTER, ModelType.STRING, true)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition NEW_IDENTITY_PARENT_DN = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.NEW_IDENTITY_PARENT_DN, ModelType.STRING, true)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] {
                RDN_IDENTIFIER, USE_RECURSIVE_SEARCH, SEARCH_BASE_DN,
                ATTRIBUTE_MAPPINGS,
                ITERATOR_FILTER, NEW_IDENTITY_PARENT_DN, NEW_IDENTITY_ATTRIBUTES
        };

        static final ObjectTypeAttributeDefinition OBJECT_DEFINITION = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.IDENTITY_MAPPING,
                    RDN_IDENTIFIER, USE_RECURSIVE_SEARCH, SEARCH_BASE_DN,
                    ATTRIBUTE_MAPPINGS,
                    ITERATOR_FILTER, NEW_IDENTITY_PARENT_DN, NEW_IDENTITY_ATTRIBUTES,
                    UserPasswordCredentialMappingObjectDefinition.OBJECT_DEFINITION,
                    OtpCredentialMappingObjectDefinition.OBJECT_DEFINITION
                )
                .setAllowNull(false)
                .build();
    }

    static final SimpleAttributeDefinition DIR_CONTEXT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.DIR_CONTEXT, ModelType.STRING, false)
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setCapabilityReference(DIR_CONTEXT_CAPABILITY, SECURITY_REALM_CAPABILITY, true)
            .build();

    static final SimpleAttributeDefinition DIRECT_VERIFICATION = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.DIRECT_VERIFICATION, ModelType.BOOLEAN, true)
        .setDefaultValue(new ModelNode(false))
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] {IdentityMappingObjectDefinition.OBJECT_DEFINITION, DIR_CONTEXT, DIRECT_VERIFICATION};

    private static final AbstractAddStepHandler ADD = new RealmAddHandler();
    private static final OperationStepHandler REMOVE = new TrivialCapabilityServiceRemoveHandler(ADD, MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY, SECURITY_REALM_RUNTIME_CAPABILITY);
    private static final OperationStepHandler WRITE = new WriteAttributeHandler();

    LdapRealmDefinition() {
        super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.LDAP_REALM), ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.LDAP_REALM))
            .setAddHandler(ADD)
            .setRemoveHandler(REMOVE)
            .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
            .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
            .setCapabilities(MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY, SECURITY_REALM_RUNTIME_CAPABILITY));
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition current : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(current, null, WRITE);
        }
    }

    private static class RealmAddHandler extends BaseAddHandler {

        private RealmAddHandler() {
            super(new HashSet<>(Arrays.asList(new RuntimeCapability[]{
                    MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY, SECURITY_REALM_RUNTIME_CAPABILITY})), ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();

            String address = context.getCurrentAddressValue();
            ServiceName mainServiceName = MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY.fromBaseCapability(address).getCapabilityServiceName();
            ServiceName aliasServiceName = SECURITY_REALM_RUNTIME_CAPABILITY.fromBaseCapability(address).getCapabilityServiceName();

            final LdapSecurityRealmBuilder builder = LdapSecurityRealmBuilder.builder();

            if (DIRECT_VERIFICATION.resolveModelAttribute(context, model).asBoolean()) {
                builder.addDirectEvidenceVerification();
            }

            TrivialService<SecurityRealm> ldapRealmService = new TrivialService<>(builder::build);
            ServiceBuilder<SecurityRealm> serviceBuilder = serviceTarget.addService(mainServiceName, ldapRealmService)
                    .addAliases(aliasServiceName);

            commonDependencies(serviceBuilder);

            configureIdentityMapping(context, model, builder);
            configureDirContext(context, model, builder, serviceBuilder);

            serviceBuilder.setInitialMode(ServiceController.Mode.ACTIVE).install();
        }

        private void configureDirContext(OperationContext context, ModelNode model, LdapSecurityRealmBuilder realmBuilder, ServiceBuilder<SecurityRealm> serviceBuilder) throws OperationFailedException {
            String dirContextName = asStringIfDefined(context, DIR_CONTEXT, model);

            String runtimeCapability = RuntimeCapability.buildDynamicCapabilityName(DIR_CONTEXT_CAPABILITY, dirContextName);
            ServiceName dirContextServiceName = context.getCapabilityServiceName(runtimeCapability, ExceptionSupplier.class);

            final InjectedValue<ExceptionSupplier> dirContextInjector = new InjectedValue<>();
            serviceBuilder.addDependency(dirContextServiceName, ExceptionSupplier.class, dirContextInjector);

            realmBuilder.setDirContextSupplier(() -> {
                @SuppressWarnings("unchecked")
                ExceptionSupplier<DirContext, NamingException> supplier = dirContextInjector.getValue();
                return supplier.get();
            });
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

            for (Map.Entry<String, CredentialMappingObjectDefinition> entry : SUPPORTED_CREDENTIAL_MAPPERS.entrySet()) {
                ModelNode node = model.get(IDENTITY_MAPPING).get(entry.getKey());
                entry.getValue().configure(builder, node);
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

            ModelNode iteratorFilterNode = IdentityMappingObjectDefinition.ITERATOR_FILTER.resolveModelAttribute(context, principalMappingNode);

            if (iteratorFilterNode.isDefined()) {
                identityMappingBuilder.setIteratorFilter(iteratorFilterNode.asString());
            }

            ModelNode newIdentityParentDnNode = IdentityMappingObjectDefinition.NEW_IDENTITY_PARENT_DN.resolveModelAttribute(context, principalMappingNode);

            if (newIdentityParentDnNode.isDefined()) {
                try {
                    identityMappingBuilder.setNewIdentityParent(new LdapName(newIdentityParentDnNode.asString()));
                } catch (InvalidNameException e) {
                    throw new OperationFailedException(e);
                }
            }

            ModelNode newIdentityAttributesNode = IdentityMappingObjectDefinition.NEW_IDENTITY_ATTRIBUTES.resolveModelAttribute(context, principalMappingNode);

            if (newIdentityAttributesNode.isDefined()) {
                Attributes attributes = new BasicAttributes(true);
                for (ModelNode attributeNode : newIdentityAttributesNode.asList()) {
                    ModelNode nameNode = NewIdentityAttributeObjectDefinition.NAME.resolveModelAttribute(context, attributeNode);
                    ModelNode valuesNode = NewIdentityAttributeObjectDefinition.VALUE.resolveModelAttribute(context, attributeNode);

                    if (valuesNode.getType() == ModelType.LIST) {
                        BasicAttribute listAttribute = new BasicAttribute(nameNode.asString());
                        for (ModelNode valueNode : valuesNode.asList()) {
                            listAttribute.add(valueNode.asString());
                        }
                        attributes.put(listAttribute);
                    } else {
                        attributes.put(new BasicAttribute(nameNode.asString(), valuesNode.asString()));
                    }
                }
                identityMappingBuilder.setNewIdentityAttributes(attributes);
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
            return MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY.fromBaseCapability(pathAddress.getLastElement().getValue())
                    .getCapabilityServiceName();
        }
    }
}