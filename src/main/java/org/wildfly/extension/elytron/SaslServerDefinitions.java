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

import static org.wildfly.extension.elytron.Capabilities.PROVIDERS_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_SERVER_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_SERVER_FACTORY_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.MODULE;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.SLOT;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.resolveClassLoader;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEY;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PROPERTY;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.VALUE;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.SecurityActions.doPrivileged;

import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import javax.security.sasl.SaslServerFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.AttributeMarshaller;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.ServiceRemoveStepHandler;
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
import org.jboss.msc.service.StartException;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.sasl.util.AggregateSaslServerFactory;
import org.wildfly.security.sasl.util.PropertiesSaslServerFactory;
import org.wildfly.security.sasl.util.ProtocolSaslServerFactory;
import org.wildfly.security.sasl.util.SecurityProviderSaslServerFactory;
import org.wildfly.security.sasl.util.ServerNameSaslServerFactory;
import org.wildfly.security.sasl.util.ServiceLoaderSaslServerFactory;

/**
 * The {@link ResourceDefinition} instances for the {@link SaslServerFactory} resources.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SaslServerDefinitions {

    static final SimpleAttributeDefinition SERVER_NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SERVER_NAME, ModelType.STRING, true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition PROTOCOL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PROTOCOL, ModelType.STRING, true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition SASL_SERVER_FACTORY = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SASL_SERVER_FACTORY, ModelType.STRING, false)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(SASL_SERVER_FACTORY_CAPABILITY, SASL_SERVER_FACTORY_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition PROVIDER_LOADER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PROVIDER_LOADER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(PROVIDERS_CAPABILITY, SASL_SERVER_FACTORY_CAPABILITY, true)
        .build();

    static final SimpleMapAttributeDefinition PROPERTIES = new SimpleMapAttributeDefinition.Builder(ElytronDescriptionConstants.PROPERTIES, ModelType.STRING, true)
        .setAttributeMarshaller(new AttributeMarshaller() {

            @Override
            public void marshallAsElement(AttributeDefinition attribute, ModelNode resourceModel, boolean marshallDefault,
                    XMLStreamWriter writer) throws XMLStreamException {
                resourceModel = resourceModel.get(attribute.getName());
                if (resourceModel.isDefined()) {
                    writer.writeStartElement(attribute.getName());
                    for (ModelNode property : resourceModel.asList()) {
                        writer.writeEmptyElement(PROPERTY);
                        writer.writeAttribute(KEY, property.asProperty().getName());
                        writer.writeAttribute(VALUE, property.asProperty().getValue().asString());
                    }
                    writer.writeEndElement();
                }
            }

        }).build();

    private static final AggregateComponentDefinition<SaslServerFactory> AGGREGATE_SASL_SERVER_FACTORY = AggregateComponentDefinition.create(SaslServerFactory.class,
            ElytronDescriptionConstants.AGGREGATE_SASL_SERVER_FACTORY, ElytronDescriptionConstants.SASL_SERVER_FACTORIES, SASL_SERVER_FACTORY_RUNTIME_CAPABILITY,
            (SaslServerFactory[] n) -> new AggregateSaslServerFactory(n));

    static AggregateComponentDefinition<SaslServerFactory> getAggregateSaslServerFactoryDefinition() {
        return AGGREGATE_SASL_SERVER_FACTORY;
    }

    static ResourceDefinition getConfiguredSaslServerFactoryDefinition() {
        AttributeDefinition[] attributes = new AttributeDefinition[] { SASL_SERVER_FACTORY, SERVER_NAME, PROTOCOL, PROPERTIES };
        AbstractAddStepHandler add = new SaslServerAddHander(attributes) {

            @Override
            protected ServiceBuilder<SaslServerFactory> installService(OperationContext context,
                    ServiceName saslServerFactoryName, ModelNode model) throws OperationFailedException {

                final String saslServerFactory = SASL_SERVER_FACTORY.resolveModelAttribute(context, model).asString();
                final String protocol = asStringIfDefined(context, PROTOCOL, model);
                final String serverName = asStringIfDefined(context, SERVER_NAME, model);

                final Map<String, String> propertiesMap;
                ModelNode properties = PROPERTIES.resolveModelAttribute(context, model);
                if (properties.isDefined()) {
                    propertiesMap = new HashMap<String, String>();
                    properties.asPropertyList().forEach((Property p) -> propertiesMap.put(p.getName(), p.getValue().asString()));
                } else {
                    propertiesMap = null;
                }

                final InjectedValue<SaslServerFactory> saslServerFactoryInjector = new InjectedValue<SaslServerFactory>();

                TrivialService<SaslServerFactory> saslServiceFactoryService = new TrivialService<SaslServerFactory>(() -> {
                    SaslServerFactory theFactory = saslServerFactoryInjector.getValue();
                    theFactory = protocol != null ? new ProtocolSaslServerFactory(theFactory, protocol) : theFactory;
                    theFactory = serverName != null ? new ServerNameSaslServerFactory(theFactory, serverName) : theFactory;
                    theFactory = propertiesMap != null ? new PropertiesSaslServerFactory(theFactory, propertiesMap) : theFactory;
                    return theFactory;
                });

                ServiceTarget serviceTarget = context.getServiceTarget();

                ServiceBuilder<SaslServerFactory> serviceBuilder = serviceTarget.addService(saslServerFactoryName, saslServiceFactoryService);

                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        RuntimeCapability.buildDynamicCapabilityName(SASL_SERVER_FACTORY_CAPABILITY, saslServerFactory),
                        SaslServerFactory.class), SaslServerFactory.class, saslServerFactoryInjector);

                return serviceBuilder;
            }

        };

        return new SaslServerResourceDefinition(ElytronDescriptionConstants.CONFIGURABLE_SASL_SERVER_FACTORY, add, attributes);
    }

    static ResourceDefinition getProviderSaslServerFactoryDefintion() {
        AbstractAddStepHandler add = new SaslServerAddHander(PROVIDER_LOADER) {

            @Override
            protected ServiceBuilder<SaslServerFactory> installService(OperationContext context,
                    ServiceName saslServerFactoryName, ModelNode model) throws OperationFailedException {

                String provider = asStringIfDefined(context, PROVIDER_LOADER, model);

                final InjectedValue<Provider[]> providerInjector = new InjectedValue<Provider[]>();
                final Supplier<Provider[]> providerSupplier = provider != null ? (() -> providerInjector.getValue()) : (() -> Security.getProviders());

                TrivialService<SaslServerFactory> saslServiceFactoryService = new TrivialService<SaslServerFactory>(() -> new SecurityProviderSaslServerFactory(providerSupplier));

                ServiceTarget serviceTarget = context.getServiceTarget();

                ServiceBuilder<SaslServerFactory> serviceBuilder = serviceTarget.addService(saslServerFactoryName, saslServiceFactoryService);

                if (provider != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(RuntimeCapability.buildDynamicCapabilityName(PROVIDERS_CAPABILITY, provider),
                            Provider[].class), Provider[].class, providerInjector);
                }

                return serviceBuilder;
            }
        };

        return new SaslServerResourceDefinition(ElytronDescriptionConstants.PROVIDER_SASL_SERVER_FACTORY, add, PROVIDER_LOADER);
    }

    static ResourceDefinition getServiceLoaderSaslServerFactoryDefinition() {
        AbstractAddStepHandler add = new SaslServerAddHander(MODULE, SLOT) {

            @Override
            protected ValueSupplier<SaslServerFactory> getValueSupplier(OperationContext context, ModelNode model)
                    throws OperationFailedException {

                final String module = asStringIfDefined(context, MODULE, model);
                final String slot = asStringIfDefined(context, SLOT, model);

                return () -> getSaslServerFactory(module, slot);
            }

            private SaslServerFactory getSaslServerFactory(final String module, final String slot) throws StartException {
                try {
                    ClassLoader classLoader = doPrivileged((PrivilegedExceptionAction<ClassLoader>) () -> resolveClassLoader(module, slot));

                    return new ServiceLoaderSaslServerFactory(classLoader);
                } catch (Exception e) {
                    throw new StartException(e);
                }
            }
        };

        return new SaslServerResourceDefinition(ElytronDescriptionConstants.SERVICE_LOADER_SASL_SERVER_FACTORY, add, MODULE, SLOT);
    }


    private static class SaslServerResourceDefinition extends SimpleResourceDefinition {

        private final String pathKey;
        private final AttributeDefinition[] attributes;

        SaslServerResourceDefinition(String pathKey, AbstractAddStepHandler add, AttributeDefinition ... attributes) {
            super(new Parameters(PathElement.pathElement(pathKey),
                    ElytronExtension.getResourceDescriptionResolver(pathKey))
                .setAddHandler(add)
                .setRemoveHandler(new RoleMapperRemoveHandler(add))
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
            this.pathKey = pathKey;
            this.attributes = attributes;
        }

        @Override
        public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
             if (attributes != null && attributes.length > 0) {
                 WriteAttributeHandler write = new WriteAttributeHandler(pathKey, attributes);
                 for (AttributeDefinition current : attributes) {
                     resourceRegistration.registerReadWriteAttribute(current, null, write);
                 }
             }
        }

    }

    private static class SaslServerAddHander extends AbstractAddStepHandler {


        private SaslServerAddHander(AttributeDefinition ... attributes) {
            super(SASL_SERVER_FACTORY_RUNTIME_CAPABILITY, attributes);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            RuntimeCapability<Void> runtimeCapability = SASL_SERVER_FACTORY_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName saslServerFactoryName = runtimeCapability.getCapabilityServiceName(SaslServerFactory.class);

            commonDependencies(installService(context, saslServerFactoryName, model))
                .setInitialMode(Mode.LAZY)
                .install();
        }

        protected ServiceBuilder<SaslServerFactory> installService(OperationContext context, ServiceName saslServerFactoryName, ModelNode model) throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            TrivialService<SaslServerFactory> saslServerFactoryService = new TrivialService<SaslServerFactory>(getValueSupplier(context, model));

            return serviceTarget.addService(saslServerFactoryName, saslServerFactoryService);
        }

        protected ValueSupplier<SaslServerFactory> getValueSupplier(OperationContext context, ModelNode model) throws OperationFailedException {
            return () -> null;
        };

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler(String parentName, AttributeDefinition ... attributes) {
            super(parentName, attributes);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress pathAddress) {
            return SASL_SERVER_FACTORY_RUNTIME_CAPABILITY.fromBaseCapability(pathAddress.getLastElement().getValue()).getCapabilityServiceName(SaslServerFactory.class);
        }
    }

    private static class RoleMapperRemoveHandler extends ServiceRemoveStepHandler {

        public RoleMapperRemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation, SASL_SERVER_FACTORY_RUNTIME_CAPABILITY);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return SASL_SERVER_FACTORY_RUNTIME_CAPABILITY.fromBaseCapability(name).getCapabilityServiceName(SaslServerFactory.class);
        }

    }
}
