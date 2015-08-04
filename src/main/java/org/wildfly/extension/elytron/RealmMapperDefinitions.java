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

import static org.wildfly.extension.elytron.Capabilities.REALM_MAPPER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.REALM_MAPPER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.FROM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALM_MAPPING;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.TO;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.RegexAttributeDefinitions.PATTERN;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.AttributeMarshaller;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleMapAttributeDefinition;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.dmr.Property;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.auth.util.MappedRegexRealmMapper;
import org.wildfly.security.auth.util.SimpleRegexRealmMapper;


/**
 * Holder class for the {@link RealmMapper} definitions.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class RealmMapperDefinitions {

    static final SimpleAttributeDefinition DELEGATE_REALM_MAPPER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.DELEGATE_REALM_MAPPER, ModelType.STRING, true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(REALM_MAPPER_CAPABILITY, REALM_MAPPER_CAPABILITY, true)
        .build();

    static final SimpleMapAttributeDefinition REALM_REALM_MAP = new SimpleMapAttributeDefinition.Builder(ElytronDescriptionConstants.REALM_MAP, ModelType.STRING, true)
        .setAttributeMarshaller(new AttributeMarshaller() {

                @Override
                public void marshallAsElement(AttributeDefinition attribute, ModelNode resourceModel, boolean marshallDefault,
                        XMLStreamWriter writer) throws XMLStreamException {
                    resourceModel = resourceModel.get(attribute.getName());
                    if (resourceModel.isDefined()) {
                        for (ModelNode property : resourceModel.asList()) {
                            writer.writeEmptyElement(REALM_MAPPING);
                            writer.writeAttribute(FROM, property.asProperty().getName());
                            writer.writeAttribute(TO, property.asProperty().getValue().asString());
                            }
                        }
                    }

                })
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();


    static ResourceDefinition getSimpleRegexRealmMapperDefinition() {
        return new SimpleRegexRealmMapperDefinition();
    }

    static ResourceDefinition getMappedRegexRealmMapper() {
        return new MappedRegexRealmMapperDefinition();
    }

    private static class SimpleRegexRealmMapperDefinition extends SimpleResourceDefinition {

        private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { PATTERN, DELEGATE_REALM_MAPPER };

        private static final AbstractAddStepHandler ADD = new SimpleRegexRealmMapperAddHandler(ATTRIBUTES);
        private static final OperationStepHandler REMOVE = new SingleCapabilityServiceRemoveHandler<RealmMapper>(ADD, REALM_MAPPER_RUNTIME_CAPABILITY, RealmMapper.class);

        private SimpleRegexRealmMapperDefinition() {
            super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.SIMPLE_REGEX_REALM_MAPPER), ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.SIMPLE_REGEX_REALM_MAPPER))
                .setAddHandler(ADD)
                .setRemoveHandler(REMOVE)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
        }

        @Override
        public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
            OperationStepHandler write = new WriteAttributeHandler(ElytronDescriptionConstants.SIMPLE_REGEX_REALM_MAPPER, ATTRIBUTES);
            for (AttributeDefinition current : ATTRIBUTES) {
                resourceRegistration.registerReadWriteAttribute(current, null, write);
            }
        }

        @Override
        public void registerCapabilities(ManagementResourceRegistration resourceRegistration) {
            resourceRegistration.registerCapability(REALM_MAPPER_RUNTIME_CAPABILITY);
        }

    }

    private static class SimpleRegexRealmMapperAddHandler extends AbstractAddStepHandler {

        private SimpleRegexRealmMapperAddHandler(final AttributeDefinition[] attributes) {
            super(REALM_MAPPER_RUNTIME_CAPABILITY, attributes);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<Void> runtimeCapability = REALM_MAPPER_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName realmMapperName = runtimeCapability.getCapabilityServiceName(RealmMapper.class);

            final String pattern = PATTERN.resolveModelAttribute(context, model).asString();
            String delegateRealmMapper = asStringIfDefined(context, DELEGATE_REALM_MAPPER, model);

            final InjectedValue<RealmMapper> delegateRealmMapperInjector = new InjectedValue<RealmMapper>();

            TrivialService<RealmMapper> realmMapperService = new TrivialService<RealmMapper>(() -> {
                RealmMapper delegate = delegateRealmMapperInjector.getOptionalValue();
                Pattern compiledPattern = Pattern.compile(pattern);
                if (delegate == null) {
                    return new SimpleRegexRealmMapper(compiledPattern);
                } else {
                    return new SimpleRegexRealmMapper(compiledPattern, delegate);
                }
            });

            ServiceBuilder<RealmMapper> realmMapperBuilder = serviceTarget.addService(realmMapperName, realmMapperService);

            if (delegateRealmMapper != null) {
                String delegateCapabilityName = RuntimeCapability.buildDynamicCapabilityName(REALM_MAPPER_CAPABILITY, delegateRealmMapper);
                ServiceName delegateServiceName = context.getCapabilityServiceName(delegateCapabilityName, RealmMapper.class);

                realmMapperBuilder.addDependency(delegateServiceName, RealmMapper.class, delegateRealmMapperInjector);
            }

            commonDependencies(realmMapperBuilder)
                .setInitialMode(Mode.LAZY)
                .install();
        }

    }

    private static class MappedRegexRealmMapperDefinition extends SimpleResourceDefinition {

        private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { PATTERN, REALM_REALM_MAP, DELEGATE_REALM_MAPPER };

        private static final AbstractAddStepHandler ADD = new MappedRegexRealmMapperAddHandler(ATTRIBUTES);
        private static final OperationStepHandler REMOVE = new SingleCapabilityServiceRemoveHandler<RealmMapper>(ADD, REALM_MAPPER_RUNTIME_CAPABILITY, RealmMapper.class);

        private MappedRegexRealmMapperDefinition() {
            super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.MAPPED_REGEX_REALM_MAPPER), ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.MAPPED_REGEX_REALM_MAPPER))
                .setAddHandler(ADD)
                .setRemoveHandler(REMOVE)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
        }

        @Override
        public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
            OperationStepHandler write = new WriteAttributeHandler(ElytronDescriptionConstants.MAPPED_REGEX_REALM_MAPPER, ATTRIBUTES);
            for (AttributeDefinition current : ATTRIBUTES) {
                resourceRegistration.registerReadWriteAttribute(current, null, write);
            }
        }

        @Override
        public void registerCapabilities(ManagementResourceRegistration resourceRegistration) {
            resourceRegistration.registerCapability(REALM_MAPPER_RUNTIME_CAPABILITY);
        }

    }

    private static class MappedRegexRealmMapperAddHandler extends AbstractAddStepHandler {

        private MappedRegexRealmMapperAddHandler(final AttributeDefinition[] attributes) {
            super(REALM_MAPPER_RUNTIME_CAPABILITY, attributes);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<Void> runtimeCapability = REALM_MAPPER_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName realmMapperName = runtimeCapability.getCapabilityServiceName(RealmMapper.class);

            final String pattern = PATTERN.resolveModelAttribute(context, model).asString();

            List<Property> realmMapList = REALM_REALM_MAP.resolveModelAttribute(context, model).asPropertyList();
            final Map<String, String> realmRealmMap = new HashMap<String, String>(realmMapList.size());
            realmMapList.forEach((Property p) -> realmRealmMap.put(p.getName(), p.getValue().asString()));

            String delegateRealmMapper = asStringIfDefined(context, DELEGATE_REALM_MAPPER, model);

            final InjectedValue<RealmMapper> delegateRealmMapperInjector = new InjectedValue<RealmMapper>();

            TrivialService<RealmMapper> realmMapperService = new TrivialService<RealmMapper>(() -> {
                RealmMapper delegate = delegateRealmMapperInjector.getOptionalValue();
                Pattern compiledPattern = Pattern.compile(pattern);
                if (delegate == null) {
                    return new MappedRegexRealmMapper(compiledPattern, realmRealmMap);
                } else {
                    return new MappedRegexRealmMapper(compiledPattern, delegate, realmRealmMap);
                }
            });

            ServiceBuilder<RealmMapper> realmMapperBuilder = serviceTarget.addService(realmMapperName, realmMapperService);

            if (delegateRealmMapper != null) {
                String delegateCapabilityName = RuntimeCapability.buildDynamicCapabilityName(REALM_MAPPER_CAPABILITY, delegateRealmMapper);
                ServiceName delegateServiceName = context.getCapabilityServiceName(delegateCapabilityName, RealmMapper.class);

                realmMapperBuilder.addDependency(delegateServiceName, RealmMapper.class, delegateRealmMapperInjector);
            }

            commonDependencies(realmMapperBuilder)
                .setInitialMode(Mode.LAZY)
                .install();
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler(String parentName, AttributeDefinition ... attributes) {
            super(parentName, attributes);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress pathAddress) {
            return REALM_MAPPER_RUNTIME_CAPABILITY.fromBaseCapability(pathAddress.getLastElement().getValue()).getCapabilityServiceName(RealmMapper.class);
        }
    }

}
