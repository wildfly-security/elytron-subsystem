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

import static org.wildfly.extension.elytron.AvailableMechanismsRuntimeResource.wrap;
import static org.jboss.as.controller.capability.RuntimeCapability.buildDynamicCapabilityName;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_AUTHENTICATION_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_SERVER_AUTHENTICATION_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_SERVER_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.NAME_REWRITER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_FACTORY_CREDENTIAL_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronExtension.getRequiredService;

import java.util.Collection;
import java.util.Collections;

import javax.security.sasl.SaslServerFactory;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectListAttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.State;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.SaslAuthenticationFactory;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * The {@link ResourceDefinition} instances for the authentication factory definitions.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class AuthenticationFactoryDefinitions {

    static final SimpleAttributeDefinition BASE_SECURITY_DOMAIN_REF = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SECURITY_DOMAIN, ModelType.STRING, false)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition HTTP_SERVER_FACTORY = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.HTTP_SERVER_FACTORY, ModelType.STRING, false)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setCapabilityReference(HTTP_SERVER_FACTORY_CAPABILITY, HTTP_SERVER_AUTHENTICATION_CAPABILITY, true)
            .build();

    static final SimpleAttributeDefinition SASL_SERVER_FACTORY = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SASL_SERVER_FACTORY, ModelType.STRING, false)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setCapabilityReference(SASL_SERVER_FACTORY_CAPABILITY, SASL_SERVER_AUTHENTICATION_CAPABILITY, true)
            .build();

    static final SimpleAttributeDefinition MECHANISM_NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.MECHANISM_NAME, ModelType.STRING, false)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition BASE_CREDENTIAL_SECURITY_FACTORY = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CREDENTIAL_SECURITY_FACTORY, ModelType.STRING, true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition BASE_PRE_REALM_NAME_REWRITER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PRE_REALM_NAME_REWRITER, ModelType.STRING, true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition BASE_POST_REALM_NAME_REWRITER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.POST_REALM_NAME_REWRITER, ModelType.STRING, true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition BASE_FINAL_NAME_REWRITER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.FINAL_NAME_REWRITER, ModelType.STRING, true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition REALM_NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REALM_NAME, ModelType.STRING, false)
            .setMinSize(1)
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    private static AttributeDefinition getMechanismConfiguration(String forCapability) {
        SimpleAttributeDefinition preRealmNameRewriterAttribute = new SimpleAttributeDefinitionBuilder(BASE_PRE_REALM_NAME_REWRITER)
                .setCapabilityReference(NAME_REWRITER_CAPABILITY, forCapability, true)
                .build();
        SimpleAttributeDefinition postRealmNameRewriterAttribute = new SimpleAttributeDefinitionBuilder(BASE_POST_REALM_NAME_REWRITER)
                .setCapabilityReference(NAME_REWRITER_CAPABILITY, forCapability, true)
                .build();
        SimpleAttributeDefinition finalNameRewriterAttribute = new SimpleAttributeDefinitionBuilder(BASE_FINAL_NAME_REWRITER)
                .setCapabilityReference(NAME_REWRITER_CAPABILITY, forCapability, true)
                .build();

        ObjectTypeAttributeDefinition mechanismRealmConfguration = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_REALM_CONFIGURATION, REALM_NAME, preRealmNameRewriterAttribute, postRealmNameRewriterAttribute, finalNameRewriterAttribute)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        ObjectListAttributeDefinition mechanismRealmConfigurations = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_REALM_CONFIGURATIONS, mechanismRealmConfguration)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        SimpleAttributeDefinition credentialSecurityFactoryAttribute = new SimpleAttributeDefinitionBuilder(BASE_CREDENTIAL_SECURITY_FACTORY)
                .setCapabilityReference(SECURITY_FACTORY_CREDENTIAL_CAPABILITY, forCapability, true)
                .build();

        ObjectTypeAttributeDefinition mechanismConfiguration = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_CONFIGURATION, MECHANISM_NAME, preRealmNameRewriterAttribute, postRealmNameRewriterAttribute, finalNameRewriterAttribute, mechanismRealmConfigurations, credentialSecurityFactoryAttribute)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        return new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_CONFIGURATIONS, mechanismConfiguration)
                .setAllowNull(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();
    }

    static ResourceDefinition getSecurityDomainHttpServerConfiguration() {

        SimpleAttributeDefinition securityDomainAttribute = new SimpleAttributeDefinitionBuilder(BASE_SECURITY_DOMAIN_REF)
                .setCapabilityReference(SECURITY_DOMAIN_CAPABILITY, HTTP_SERVER_AUTHENTICATION_CAPABILITY, true)
                .build();

        AttributeDefinition[] attributes = new AttributeDefinition[] { securityDomainAttribute, HTTP_SERVER_FACTORY, getMechanismConfiguration(HTTP_SERVER_AUTHENTICATION_CAPABILITY) };
        AbstractAddStepHandler add = new TrivialAddHandler<HttpAuthenticationFactory>(HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY, HttpAuthenticationFactory.class, attributes) {

            @Override
            protected ValueSupplier<HttpAuthenticationFactory> getValueSupplier(
                    ServiceBuilder<HttpAuthenticationFactory> serviceBuilder, OperationContext context, ModelNode model)
                    throws OperationFailedException {

                final InjectedValue<SecurityDomain> securityDomainInjector = new InjectedValue<SecurityDomain>();
                final InjectedValue<HttpServerAuthenticationMechanismFactory> mechanismFactoryInjector = new InjectedValue<HttpServerAuthenticationMechanismFactory>();

                String securityDomain = securityDomainAttribute.resolveModelAttribute(context, model).asString();
                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(SECURITY_DOMAIN_CAPABILITY, securityDomain), SecurityDomain.class),
                        SecurityDomain.class, securityDomainInjector);

                String httpServerFactory = HTTP_SERVER_FACTORY.resolveModelAttribute(context, model).asString();
                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(HTTP_SERVER_FACTORY_CAPABILITY, httpServerFactory), HttpServerAuthenticationMechanismFactory.class),
                        HttpServerAuthenticationMechanismFactory.class, mechanismFactoryInjector);

                return () -> {
                    HttpServerAuthenticationMechanismFactory injectedHttpServerFactory = mechanismFactoryInjector.getValue();

                    HttpAuthenticationFactory.Builder builder = HttpAuthenticationFactory.builder()
                            .setSecurityDomain(securityDomainInjector.getValue())
                            .setHttpServerAuthenticationMechanismFactory(injectedHttpServerFactory);

                    MechanismConfiguration defaultConfig = MechanismConfiguration.builder()
                            .build();

                    for (String mech :injectedHttpServerFactory.getMechanismNames(Collections.emptyMap())) {
                        builder.addMechanism(mech, defaultConfig);
                    }

                    return builder.build();
                };
            }
        };

        return wrap(new TrivialResourceDefinition<>(ElytronDescriptionConstants.HTTP_SERVER_AUTHENITCATION, HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY,
                HttpAuthenticationFactory.class, add, attributes), AuthenticationFactoryDefinitions::getAvailableHttpMechanisms);
    }

    private static String[] getAvailableHttpMechanisms(OperationContext context) {
        RuntimeCapability<Void> runtimeCapability = HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
        ServiceName securityDomainHttpConfigurationName = runtimeCapability.getCapabilityServiceName(HttpAuthenticationFactory.class);

        ServiceController<HttpAuthenticationFactory> serviceContainer = getRequiredService(context.getServiceRegistry(false), securityDomainHttpConfigurationName, HttpAuthenticationFactory.class);
        if (serviceContainer.getState() != State.UP) {
            return null;
        }

        Collection<String> mechanismNames = serviceContainer.getValue().getMechanismNames();
        return  mechanismNames.toArray(new String[mechanismNames.size()]);
    }

    static ResourceDefinition getSecurityDomainSaslConfiguration() {
        SimpleAttributeDefinition securityDomainAttribute = new SimpleAttributeDefinitionBuilder(BASE_SECURITY_DOMAIN_REF)
                .setCapabilityReference(SECURITY_DOMAIN_CAPABILITY, SASL_SERVER_AUTHENTICATION_CAPABILITY, true)
                .build();

        AttributeDefinition[] attributes = new AttributeDefinition[] { securityDomainAttribute, SASL_SERVER_FACTORY, getMechanismConfiguration(SASL_SERVER_AUTHENTICATION_CAPABILITY) };

        AbstractAddStepHandler add = new TrivialAddHandler<SaslAuthenticationFactory>(SASL_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY, SaslAuthenticationFactory.class, attributes) {

            @Override
            protected ValueSupplier<SaslAuthenticationFactory> getValueSupplier(
                    ServiceBuilder<SaslAuthenticationFactory> serviceBuilder, OperationContext context, ModelNode model)
                    throws OperationFailedException {

                String securityDomain = securityDomainAttribute.resolveModelAttribute(context, model).asString();
                String saslServerFactory = SASL_SERVER_FACTORY.resolveModelAttribute(context, model).asString();

                final InjectedValue<SecurityDomain> securityDomainInjector = new InjectedValue<SecurityDomain>();
                final InjectedValue<SaslServerFactory> saslServerFactoryInjector = new InjectedValue<SaslServerFactory>();

                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(SECURITY_DOMAIN_CAPABILITY, securityDomain), SecurityDomain.class),
                        SecurityDomain.class, securityDomainInjector);

                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(SASL_SERVER_FACTORY_CAPABILITY, saslServerFactory), SaslServerFactory.class),
                        SaslServerFactory.class, saslServerFactoryInjector);

                return () -> {
                    SaslServerFactory injectedSaslServerFactory = saslServerFactoryInjector.getValue();

                    SaslAuthenticationFactory.Builder builder = SaslAuthenticationFactory.builder()
                            .setSecurityDomain(securityDomainInjector.getValue())
                            .setSaslServerFactory(injectedSaslServerFactory);

                    MechanismConfiguration defaultConfig = MechanismConfiguration.builder()
                            .build();

                    for (String mech :injectedSaslServerFactory.getMechanismNames(Collections.emptyMap())) {
                        builder.addMechanism(mech, defaultConfig);
                    }

                    return builder.build();
                };
            }
        };

        return wrap(new TrivialResourceDefinition<SaslAuthenticationFactory>(ElytronDescriptionConstants.SASL_SERVER_AUTHENTICATION,
                SASL_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY, SaslAuthenticationFactory.class, add, attributes), AuthenticationFactoryDefinitions::getAvailableSaslMechanisms);
    }

    private static String[] getAvailableSaslMechanisms(OperationContext context) {
        RuntimeCapability<Void> runtimeCapability = SASL_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
        ServiceName securityDomainSaslConfigurationName = runtimeCapability.getCapabilityServiceName(SaslAuthenticationFactory.class);

        ServiceController<SaslAuthenticationFactory> serviceContainer = getRequiredService(context.getServiceRegistry(false), securityDomainSaslConfigurationName, SaslAuthenticationFactory.class);
        if (serviceContainer.getState() != State.UP) {
            return null;
        }

        Collection<String> mechanismNames = serviceContainer.getValue().getMechanismNames();
        return  mechanismNames.toArray(new String[mechanismNames.size()]);
    }

}
