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

import static org.jboss.as.controller.capability.RuntimeCapability.buildDynamicCapabilityName;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.PROVIDERS_CAPABILITY;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.MODULE;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.SLOT;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.resolveClassLoader;
import static org.wildfly.extension.elytron.CommonAttributes.PROPERTIES;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.SecurityActions.doPrivileged;

import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.dmr.Property;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.StartException;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.AggregateServerMechanismFactory;
import org.wildfly.security.http.util.PropertiesServerMechanismFactory;
import org.wildfly.security.http.util.SecurityProviderServerMechanismFactory;
import org.wildfly.security.http.util.ServiceLoaderServerMechanismFactory;

/**
 * Resource definitions for loading and configuring the HTTP server side authentication mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class HttpServerDefinitions {

    static final SimpleAttributeDefinition HTTP_SERVER_FACTORY = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.HTTP_SERVER_FACTORY, ModelType.STRING, false)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(HTTP_SERVER_FACTORY_CAPABILITY, HTTP_SERVER_FACTORY_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition PROVIDER_LOADER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PROVIDER_LOADER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(PROVIDERS_CAPABILITY, HTTP_SERVER_FACTORY_CAPABILITY, true)
        .build();

    private static final AggregateComponentDefinition<HttpServerAuthenticationMechanismFactory> AGGREGATE_HTTP_SERVER_FACTORY = AggregateComponentDefinition.create(HttpServerAuthenticationMechanismFactory.class,
            ElytronDescriptionConstants.AGGREGATE_HTTP_SERVER_FACTORY, ElytronDescriptionConstants.HTTP_SERVER_FACTORIES, HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY,
            (HttpServerAuthenticationMechanismFactory[] n) -> new AggregateServerMechanismFactory(n));

    static ResourceDefinition getAggregateHttpServerFactoryDefintion() {
        return AGGREGATE_HTTP_SERVER_FACTORY;
    }

    static ResourceDefinition getConfigurableHttpServerFactoryDefinition() {
        AttributeDefinition[] attributes = new AttributeDefinition[] { HTTP_SERVER_FACTORY, PROPERTIES };
        AbstractAddStepHandler add = new TrivialAddHandler<HttpServerAuthenticationMechanismFactory>(HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY, HttpServerAuthenticationMechanismFactory.class, attributes) {

            @Override
            protected ValueSupplier<HttpServerAuthenticationMechanismFactory> getValueSupplier(
                    ServiceBuilder<HttpServerAuthenticationMechanismFactory> serviceBuilder, OperationContext context,
                    ModelNode model) throws OperationFailedException {

                final InjectedValue<HttpServerAuthenticationMechanismFactory> factoryInjector = new InjectedValue<HttpServerAuthenticationMechanismFactory>();

                String httpServerFactory = HTTP_SERVER_FACTORY.resolveModelAttribute(context, model).asString();
                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(HTTP_SERVER_FACTORY_CAPABILITY, httpServerFactory), HttpServerAuthenticationMechanismFactory.class),
                        HttpServerAuthenticationMechanismFactory.class, factoryInjector);

                final Map<String, String> propertiesMap;
                ModelNode properties = PROPERTIES.resolveModelAttribute(context, model);
                if (properties.isDefined()) {
                    propertiesMap = new HashMap<String, String>();
                    properties.asPropertyList().forEach((Property p) -> propertiesMap.put(p.getName(), p.getValue().asString()));
                } else {
                    propertiesMap = null;
                }

                return () -> new PropertiesServerMechanismFactory(factoryInjector.getValue(), propertiesMap);
            }
        };

        return new TrivialResourceDefinition<HttpServerAuthenticationMechanismFactory>(ElytronDescriptionConstants.CONFIGURABLE_HTTP_SERVER_FACTORY, HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY,
                HttpServerAuthenticationMechanismFactory.class, add, attributes);
    }

    static ResourceDefinition getProviderHttpServerFactoryDefinition() {
        AttributeDefinition[] attributes = new AttributeDefinition[] { PROVIDER_LOADER };
        AbstractAddStepHandler add = new TrivialAddHandler<HttpServerAuthenticationMechanismFactory>(HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY, HttpServerAuthenticationMechanismFactory.class, attributes) {

            @Override
            protected ValueSupplier<HttpServerAuthenticationMechanismFactory> getValueSupplier(
                    ServiceBuilder<HttpServerAuthenticationMechanismFactory> serviceBuilder, OperationContext context,
                    ModelNode model) throws OperationFailedException {

                String provider = asStringIfDefined(context, PROVIDER_LOADER, model);
                final Supplier<Provider[]> providerSupplier;
                if (provider != null) {
                    final InjectedValue<Provider[]> providersInjector = new InjectedValue<Provider[]>();
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(PROVIDERS_CAPABILITY, provider), Provider[].class),
                            Provider[].class, providersInjector);
                    providerSupplier = providersInjector::getValue;
                } else {
                    providerSupplier = Security::getProviders;
                }

                return () -> new SecurityProviderServerMechanismFactory(providerSupplier);
            }

        };

        return new TrivialResourceDefinition<HttpServerAuthenticationMechanismFactory>(ElytronDescriptionConstants.PROVIDER_HTTP_SERVER_FACTORY, HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY,
                HttpServerAuthenticationMechanismFactory.class, add, attributes);
    }

    static ResourceDefinition getServiceLoaderServerFactoryDefinition() {
        AttributeDefinition[] attributes = new AttributeDefinition[] {MODULE, SLOT};
        AbstractAddStepHandler add = new TrivialAddHandler<HttpServerAuthenticationMechanismFactory>(HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY, HttpServerAuthenticationMechanismFactory.class, attributes) {

            @Override
            protected ValueSupplier<HttpServerAuthenticationMechanismFactory> getValueSupplier(
                    ServiceBuilder<HttpServerAuthenticationMechanismFactory> serviceBuilder, OperationContext context,
                    ModelNode model) throws OperationFailedException {
                final String module = asStringIfDefined(context, MODULE, model);
                final String slot = asStringIfDefined(context, SLOT, model);

                return () -> {
                    try {
                        ClassLoader classLoader = doPrivileged((PrivilegedExceptionAction<ClassLoader>) () -> resolveClassLoader(module, slot));

                        return new ServiceLoaderServerMechanismFactory(classLoader);
                    } catch (Exception e) {
                        throw new StartException(e);
                    }
                };

            }
        };

        return new TrivialResourceDefinition<HttpServerAuthenticationMechanismFactory>(ElytronDescriptionConstants.SERVICE_LOADER_HTTP_SERVER_FACTORY, HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY,
                HttpServerAuthenticationMechanismFactory.class, add, attributes);
    }

}
