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
import static org.wildfly.extension.elytron.AvailableMechanismsRuntimeResource.wrap;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_AUTHENTICATION_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.NAME_REWRITER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.REALM_MAPPER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_SERVER_AUTHENTICATION_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_SERVER_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_FACTORY_CREDENTIAL_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.ElytronExtension.getRequiredService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Consumer;

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
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.State;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmMapper;
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

    static final StringListAttributeDefinition BASE_CREDENTIAL_SECURITY_FACTORIES = new StringListAttributeDefinition.Builder(ElytronDescriptionConstants.CREDENTIAL_SECURITY_FACTORIES)
            .setAllowNull(true)
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

    static final SimpleAttributeDefinition BASE_REALM_MAPPER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REALM_MAPPER, ModelType.STRING, true)
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
        SimpleAttributeDefinition realmMapperAttribute = new SimpleAttributeDefinitionBuilder(BASE_REALM_MAPPER)
                .setCapabilityReference(REALM_MAPPER_CAPABILITY, forCapability, true)
                .build();

        ObjectTypeAttributeDefinition mechanismRealmConfguration = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_REALM_CONFIGURATION, REALM_NAME, preRealmNameRewriterAttribute, postRealmNameRewriterAttribute, finalNameRewriterAttribute, realmMapperAttribute)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        ObjectListAttributeDefinition mechanismRealmConfigurations = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_REALM_CONFIGURATIONS, mechanismRealmConfguration)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        StringListAttributeDefinition credentialSecurityFactoriesAttribute = new StringListAttributeDefinition.Builder(BASE_CREDENTIAL_SECURITY_FACTORIES)
                .setCapabilityReference(SECURITY_FACTORY_CREDENTIAL_CAPABILITY, forCapability, true)
                .build();

        ObjectTypeAttributeDefinition mechanismConfiguration = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_CONFIGURATION, MECHANISM_NAME, preRealmNameRewriterAttribute,
                    postRealmNameRewriterAttribute, finalNameRewriterAttribute, realmMapperAttribute, mechanismRealmConfigurations, credentialSecurityFactoriesAttribute)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        return new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_CONFIGURATIONS, mechanismConfiguration)
                .setAllowNull(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();
    }

    static Map<String, ResolvedMechanismConfiguration> getResolvedMechanismConfiguration(AttributeDefinition mechanismConfigurationAttribute, ServiceBuilder<?> serviceBuilder,
            OperationContext context, ModelNode model) throws OperationFailedException {
        ModelNode mechanismConfiguration = mechanismConfigurationAttribute.resolveModelAttribute(context, model);
        if (mechanismConfiguration.isDefined() == false) {
            return Collections.emptyMap();
        }
        List<ModelNode> mechanismConfigurations = mechanismConfiguration.asList();
        Map<String, ResolvedMechanismConfiguration> resolvedMechanismConfigurationMap = new HashMap<>(mechanismConfigurations.size());
        for (ModelNode currentMechanismConfiguration : mechanismConfigurations) {
            ResolvedMechanismConfiguration resolvedMechanismConfiguration = new ResolvedMechanismConfiguration();
            String mechanismName = MECHANISM_NAME.resolveModelAttribute(context, currentMechanismConfiguration).asString();

            injectNameRewriter(BASE_PRE_REALM_NAME_REWRITER, serviceBuilder, context, currentMechanismConfiguration, resolvedMechanismConfiguration.preRealmNameRewriter);
            injectNameRewriter(BASE_POST_REALM_NAME_REWRITER, serviceBuilder, context, currentMechanismConfiguration, resolvedMechanismConfiguration.postRealmNameRewriter);
            injectNameRewriter(BASE_FINAL_NAME_REWRITER, serviceBuilder, context, currentMechanismConfiguration, resolvedMechanismConfiguration.finalNameRewriter);
            injectRealmMapper(BASE_REALM_MAPPER, serviceBuilder, context, currentMechanismConfiguration, resolvedMechanismConfiguration.realmMapper);

            List<String> securityFactories = BASE_CREDENTIAL_SECURITY_FACTORIES.unwrap(context, currentMechanismConfiguration);

            for (String securityFactory : securityFactories) {
                InjectedValue<SecurityFactory> securityFactoryInjector = new InjectedValue<>();

                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(SECURITY_FACTORY_CREDENTIAL_CAPABILITY, securityFactory), SecurityFactory.class),
                        SecurityFactory.class, securityFactoryInjector);

                resolvedMechanismConfiguration.securityFactories.add(securityFactoryInjector);
            }

            if (currentMechanismConfiguration.hasDefined(ElytronDescriptionConstants.MECHANISM_REALM_CONFIGURATIONS)) {
                for (ModelNode currentMechanismRealm : currentMechanismConfiguration.require(ElytronDescriptionConstants.MECHANISM_REALM_CONFIGURATIONS).asList()) {
                    String realmName = REALM_NAME.resolveModelAttribute(context, currentMechanismRealm).asString();
                    ResolvedMechanismRealmConfiguration resolvedMechanismRealmConfiguration = new ResolvedMechanismRealmConfiguration();
                    injectNameRewriter(BASE_PRE_REALM_NAME_REWRITER, serviceBuilder, context, currentMechanismRealm, resolvedMechanismRealmConfiguration.preRealmNameRewriter);
                    injectNameRewriter(BASE_POST_REALM_NAME_REWRITER, serviceBuilder, context, currentMechanismRealm, resolvedMechanismRealmConfiguration.postRealmNameRewriter);
                    injectNameRewriter(BASE_FINAL_NAME_REWRITER, serviceBuilder, context, currentMechanismRealm, resolvedMechanismRealmConfiguration.finalNameRewriter);
                    injectRealmMapper(BASE_REALM_MAPPER, serviceBuilder, context, currentMechanismRealm, resolvedMechanismRealmConfiguration.realmMapper);
                    resolvedMechanismConfiguration.mechanismRealms.put(realmName, resolvedMechanismRealmConfiguration);
                }
            }

            resolvedMechanismConfigurationMap.put(mechanismName, resolvedMechanismConfiguration);
        }

        return resolvedMechanismConfigurationMap;
    }

    static void buildMechanismConfiguration(Map<String, ResolvedMechanismConfiguration> resolvedMechanismConfigurationMap, MechanismAuthenticationFactory.Builder factoryBuilder) {
        for (Entry<String, ResolvedMechanismConfiguration> currentEntry : resolvedMechanismConfigurationMap.entrySet()) {
            ResolvedMechanismConfiguration resolvedMechanismConfiguration = currentEntry.getValue();
            MechanismConfiguration.Builder builder = MechanismConfiguration.builder();

            setNameRewriter(resolvedMechanismConfiguration.preRealmNameRewriter, builder::setPreRealmRewriter);
            setNameRewriter(resolvedMechanismConfiguration.postRealmNameRewriter, builder::setPostRealmRewriter);
            setNameRewriter(resolvedMechanismConfiguration.finalNameRewriter, builder::setFinalRewriter);
            setRealmMapper(resolvedMechanismConfiguration.realmMapper, builder::setRealmMapper);

            for (Entry<String, ResolvedMechanismRealmConfiguration> currentMechRealmEntry : resolvedMechanismConfiguration.mechanismRealms.entrySet()) {
                MechanismRealmConfiguration.Builder mechRealmBuilder = MechanismRealmConfiguration.builder();
                mechRealmBuilder.setRealmName(currentMechRealmEntry.getKey());
                ResolvedMechanismRealmConfiguration resolvedMechanismRealmConfiguration = currentMechRealmEntry.getValue();

                setNameRewriter(resolvedMechanismRealmConfiguration.preRealmNameRewriter, mechRealmBuilder::setPreRealmRewriter);
                setNameRewriter(resolvedMechanismRealmConfiguration.postRealmNameRewriter, mechRealmBuilder::setPostRealmRewriter);
                setNameRewriter(resolvedMechanismRealmConfiguration.finalNameRewriter, mechRealmBuilder::setFinalRewriter);
                setRealmMapper(resolvedMechanismRealmConfiguration.realmMapper, mechRealmBuilder::setRealmMapper);

                builder.addMechanismRealm(mechRealmBuilder.build());
            }

            for (InjectedValue<SecurityFactory> securityFactory : resolvedMechanismConfiguration.securityFactories) {
                builder.addServerCredential(securityFactory.getValue());
            }

            factoryBuilder.addMechanism(currentEntry.getKey(), builder.build());
        }
    }

    private static void setNameRewriter(InjectedValue<NameRewriter> injectedValue, Consumer<NameRewriter> nameRewriterConsumer) {
        NameRewriter nameRewriter = injectedValue.getOptionalValue();
        if (nameRewriter != null) {
            nameRewriterConsumer.accept(nameRewriter);
        }
    }

    private static void injectNameRewriter(SimpleAttributeDefinition nameRewriterAttribute, ServiceBuilder<?> serviceBuilder, OperationContext context, ModelNode model, Injector<NameRewriter> preRealmNameRewriter) throws OperationFailedException {
        String nameRewriter = asStringIfDefined(context, nameRewriterAttribute, model);
        if (nameRewriter != null) {
            serviceBuilder.addDependency(context.getCapabilityServiceName(
                    buildDynamicCapabilityName(NAME_REWRITER_CAPABILITY, nameRewriter), NameRewriter.class),
                    NameRewriter.class, preRealmNameRewriter);
        }
    }

    private static void setRealmMapper(InjectedValue<RealmMapper> injectedValue, Consumer<RealmMapper> realmMapperConsumer) {
        RealmMapper realmMapper = injectedValue.getOptionalValue();
        if (realmMapper != null) {
            realmMapperConsumer.accept(realmMapper);
        }
    }

    private static void injectRealmMapper(SimpleAttributeDefinition realmMapperAttribute, ServiceBuilder<?> serviceBuilder, OperationContext context, ModelNode model, Injector<RealmMapper> realmMapperInjector) throws OperationFailedException {
        String realmMapper = asStringIfDefined(context, realmMapperAttribute, model);
        if (realmMapper != null) {
            serviceBuilder.addDependency(context.getCapabilityServiceName(
                    buildDynamicCapabilityName(REALM_MAPPER_CAPABILITY, realmMapper), RealmMapper.class),
                    RealmMapper.class, realmMapperInjector);
        }
    }

    static ResourceDefinition getSecurityDomainHttpServerConfiguration() {

        SimpleAttributeDefinition securityDomainAttribute = new SimpleAttributeDefinitionBuilder(BASE_SECURITY_DOMAIN_REF)
                .setCapabilityReference(SECURITY_DOMAIN_CAPABILITY, HTTP_SERVER_AUTHENTICATION_CAPABILITY, true)
                .build();

        AttributeDefinition mechanismConfigurationAttribute = getMechanismConfiguration(HTTP_SERVER_AUTHENTICATION_CAPABILITY);

        AttributeDefinition[] attributes = new AttributeDefinition[] { securityDomainAttribute, HTTP_SERVER_FACTORY, mechanismConfigurationAttribute };
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

                final Map<String, ResolvedMechanismConfiguration> resolvedMechanismConfiguration = getResolvedMechanismConfiguration(mechanismConfigurationAttribute, serviceBuilder, context, model);

                return () -> {
                    HttpServerAuthenticationMechanismFactory injectedHttpServerFactory = mechanismFactoryInjector.getValue();

                    HttpAuthenticationFactory.Builder builder = HttpAuthenticationFactory.builder()
                            .setSecurityDomain(securityDomainInjector.getValue())
                            .setFactory(injectedHttpServerFactory);

                    buildMechanismConfiguration(resolvedMechanismConfiguration, builder);

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

        AttributeDefinition mechanismConfigurationAttribute = getMechanismConfiguration(SASL_SERVER_AUTHENTICATION_CAPABILITY);

        AttributeDefinition[] attributes = new AttributeDefinition[] { securityDomainAttribute, SASL_SERVER_FACTORY, mechanismConfigurationAttribute };

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

                final Map<String, ResolvedMechanismConfiguration> resolvedMechanismConfiguration = getResolvedMechanismConfiguration(mechanismConfigurationAttribute, serviceBuilder, context, model);

                return () -> {
                    SaslServerFactory injectedSaslServerFactory = saslServerFactoryInjector.getValue();

                    SaslAuthenticationFactory.Builder builder = SaslAuthenticationFactory.builder()
                            .setSecurityDomain(securityDomainInjector.getValue())
                            .setFactory(injectedSaslServerFactory);

                    buildMechanismConfiguration(resolvedMechanismConfiguration, builder);

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

    private static class ResolvedMechanismRealmConfiguration {
        final InjectedValue<NameRewriter> preRealmNameRewriter = new InjectedValue<>();
        final InjectedValue<NameRewriter> postRealmNameRewriter = new InjectedValue<>();
        final InjectedValue<NameRewriter> finalNameRewriter = new InjectedValue<>();
        final InjectedValue<RealmMapper> realmMapper = new InjectedValue<>();
    }

    private static class ResolvedMechanismConfiguration extends ResolvedMechanismRealmConfiguration {
        final Map<String, ResolvedMechanismRealmConfiguration> mechanismRealms = new HashMap<>();
        final List<InjectedValue<SecurityFactory>> securityFactories = new ArrayList<>();
    }

}
