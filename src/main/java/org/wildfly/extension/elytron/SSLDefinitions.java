/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
import static org.wildfly.extension.elytron.Capabilities.KEYSTORE_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.KEY_MANAGERS_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.KEY_MANAGERS_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.PROVIDERS_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SSL_CONTEXT_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SSL_CONTEXT_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.TRUST_MANAGERS_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.TRUST_MANAGERS_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronExtension.ELYTRON_1_0_0;
import static org.wildfly.extension.elytron.ElytronExtension.allowedValues;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.ElytronExtension.getRequiredService;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AbstractRuntimeOnlyHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.operations.validation.EnumValidator;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.Resource;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.State;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.StartException;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.ssl.CipherSuiteSelector;
import org.wildfly.security.ssl.Protocol;
import org.wildfly.security.ssl.ProtocolSelector;
import org.wildfly.security.ssl.ServerSSLContextBuilder;

/**
 * Definitions for resources used to configure SSLContexts.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SSLDefinitions {

    static final ServiceUtil<SSLContext> SERVER_SSL_CONTEXT = ServiceUtil.newInstance(SSL_CONTEXT_RUNTIME_CAPABILITY, ElytronDescriptionConstants.SERVER_SSL_CONTEXT, SSLContext.class);

    static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ALGORITHM, ModelType.STRING, false)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition PROVIDER_LOADER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PROVIDER_LOADER, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition KEYSTORE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.KEYSTORE, ModelType.STRING, false)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition PASSWORD = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PASSWORD, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setDeprecated(ELYTRON_1_0_0) // Deprecate immediately as to be supplied by the vault.
            .build();

    static final SimpleAttributeDefinition SECURITY_DOMAIN = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SECURITY_DOMAIN, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setCapabilityReference(SECURITY_DOMAIN_CAPABILITY, SSL_CONTEXT_CAPABILITY, true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition CIPHER_SUITE_FILTER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CIPHER_SUITE_FILTER, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final StringListAttributeDefinition PROTOCOLS = new StringListAttributeDefinition.Builder(ElytronDescriptionConstants.PROTOCOLS)
            .setAllowExpression(true)
            .setMinSize(1)
            .setAllowedValues(allowedValues(Protocol.values()))
            .setValidator(new EnumValidator<>(Protocol.class, false, true))
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition WANT_CLIENT_AUTH = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.WANT_CLIENT_AUTH, ModelType.BOOLEAN, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(false))
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition NEED_CLIENT_AUTH = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.NEED_CLIENT_AUTH, ModelType.BOOLEAN, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(false))
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition AUTHENTICATION_OPTIONAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.AUTHENTICATION_OPTIONAL, ModelType.BOOLEAN, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(false))
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition MAXIMUM_SESSION_CACHE_SIZE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.MAXIMUM_SESSION_CACHE_SIZE, ModelType.INT, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(0))
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition SESSION_TIMEOUT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SESSION_TIMEOUT, ModelType.INT, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(0))
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition KEY_MANAGERS = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.KEY_MANAGERS, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setCapabilityReference(KEY_MANAGERS_CAPABILITY, SSL_CONTEXT_CAPABILITY, true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition TRUST_MANAGERS = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.TRUST_MANAGERS, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setCapabilityReference(TRUST_MANAGERS_CAPABILITY, SSL_CONTEXT_CAPABILITY, true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    /*
     * Runtime Attributes
     */

    private static SimpleAttributeDefinition ACTIVE_SESSION_COUNT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ACTIVE_SESSION_COUNT, ModelType.INT)
            .setStorageRuntime()
            .build();


    static ResourceDefinition getKeyManagerDefinition() {
        final SimpleAttributeDefinition providerLoaderDefinition = setCapabilityReference(PROVIDERS_CAPABILITY, KEY_MANAGERS_CAPABILITY, PROVIDER_LOADER);
        final SimpleAttributeDefinition keystoreDefinition = setCapabilityReference(KEYSTORE_CAPABILITY, KEY_MANAGERS_CAPABILITY, KEYSTORE);

        AttributeDefinition[] attributes = new AttributeDefinition[] { ALGORITHM, providerLoaderDefinition, keystoreDefinition, PASSWORD };

        AbstractAddStepHandler add = new TrivialAddHandler<KeyManager[]>(KEY_MANAGERS_RUNTIME_CAPABILITY, KeyManager[].class, attributes) {

            @Override
            protected ValueSupplier<KeyManager[]> getValueSupplier(ServiceBuilder<KeyManager[]> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {
                final String algorithm = ALGORITHM.resolveModelAttribute(context, model).asString();
                final String password = asStringIfDefined(context, PASSWORD, model);

                String providerLoader = asStringIfDefined(context, providerLoaderDefinition, model);
                final InjectedValue<Provider[]> providersInjector = new InjectedValue<>();
                if (providerLoader != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(PROVIDERS_CAPABILITY, providerLoader), Provider[].class),
                            Provider[].class, providersInjector);
                }

                String keyStore = asStringIfDefined(context, keystoreDefinition, model);
                final InjectedValue<KeyStore> keyStoreInjector = new InjectedValue<>();
                if (keyStore != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(KEYSTORE_CAPABILITY, keyStore), KeyStore.class),
                            KeyStore.class, keyStoreInjector);
                }

                return () -> {
                    Provider[] providers = providersInjector.getOptionalValue();
                    KeyManagerFactory keyManagerFactory = null;
                    if (providers != null) {
                        for (Provider current : providers) {
                            try {
                                // TODO - We could check the Services within each Provider to check there is one of the required type/algorithm
                                // However the same loop would need to remain as it is still possible a specific provider can't create it.
                                keyManagerFactory = KeyManagerFactory.getInstance(algorithm, current);
                                break;
                            } catch (NoSuchAlgorithmException ignored) {
                            }
                        }
                        throw ROOT_LOGGER.unableToCreateManagerFactory(KeyManagerFactory.class.getSimpleName(), algorithm);
                    } else {
                        try {
                            keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
                        } catch (NoSuchAlgorithmException e) {
                            throw new StartException(e);
                        }
                    }

                    try {
                        keyManagerFactory.init(keyStoreInjector.getOptionalValue(), password != null ? password.toCharArray() : null);
                    } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
                        throw new StartException(e);
                    }

                    return keyManagerFactory.getKeyManagers();
                };
            }
        };

        return new TrivialResourceDefinition<>(ElytronDescriptionConstants.KEY_MANAGERS, KEY_MANAGERS_RUNTIME_CAPABILITY, KeyManager[].class, add, attributes);

    }

    static ResourceDefinition getTrustManagerDefinition() {
        final SimpleAttributeDefinition providerLoaderDefinition = setCapabilityReference(PROVIDERS_CAPABILITY, TRUST_MANAGERS_CAPABILITY, PROVIDER_LOADER);
        final SimpleAttributeDefinition keystoreDefinition = setCapabilityReference(KEYSTORE_CAPABILITY, TRUST_MANAGERS_CAPABILITY, KEYSTORE);

        AttributeDefinition[] attributes = new AttributeDefinition[] { ALGORITHM, providerLoaderDefinition, keystoreDefinition };

        AbstractAddStepHandler add = new TrivialAddHandler<TrustManager[]>(TRUST_MANAGERS_RUNTIME_CAPABILITY, TrustManager[].class, attributes) {

            @Override
            protected ValueSupplier<TrustManager[]> getValueSupplier(ServiceBuilder<TrustManager[]> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {
                final String algorithm = ALGORITHM.resolveModelAttribute(context, model).asString();

                String providerLoader = asStringIfDefined(context, providerLoaderDefinition, model);
                final InjectedValue<Provider[]> providersInjector = new InjectedValue<>();
                if (providerLoader != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(PROVIDERS_CAPABILITY, providerLoader), Provider[].class),
                            Provider[].class, providersInjector);
                }

                String keyStore = asStringIfDefined(context, keystoreDefinition, model);
                final InjectedValue<KeyStore> keyStoreInjector = new InjectedValue<>();
                if (keyStore != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(KEYSTORE_CAPABILITY, keyStore), KeyStore.class),
                            KeyStore.class, keyStoreInjector);
                }

                return () -> {
                    Provider[] providers = providersInjector.getOptionalValue();
                    TrustManagerFactory trustManagerFactory = null;
                    if (providers != null) {
                        for (Provider current : providers) {
                            try {
                                // TODO - We could check the Services within each Provider to check there is one of the required type/algorithm
                                // However the same loop would need to remain as it is still possible a specific provider can't create it.
                                trustManagerFactory = TrustManagerFactory.getInstance(algorithm, current);
                                break;
                            } catch (NoSuchAlgorithmException ignored) {
                            }
                        }
                        throw ROOT_LOGGER.unableToCreateManagerFactory(TrustManagerFactory.class.getSimpleName(), algorithm);
                    } else {
                        try {
                            trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
                        } catch (NoSuchAlgorithmException e) {
                            throw new StartException(e);
                        }
                    }

                    try {
                        trustManagerFactory.init(keyStoreInjector.getOptionalValue());
                    } catch (KeyStoreException e) {
                        throw new StartException(e);
                    }

                    return trustManagerFactory.getTrustManagers();
                };
            }
        };

        return new TrivialResourceDefinition<>(ElytronDescriptionConstants.TRUST_MANAGERS, TRUST_MANAGERS_RUNTIME_CAPABILITY, TrustManager[].class, add, attributes);

    }

    static ResourceDefinition getServerSSLContextBuilder() {
        final SimpleAttributeDefinition providerLoaderDefinition = setCapabilityReference(PROVIDERS_CAPABILITY, SSL_CONTEXT_CAPABILITY, PROVIDER_LOADER);

        AttributeDefinition[] attributes = new AttributeDefinition[] { SECURITY_DOMAIN, CIPHER_SUITE_FILTER, PROTOCOLS, WANT_CLIENT_AUTH, NEED_CLIENT_AUTH, AUTHENTICATION_OPTIONAL,
                MAXIMUM_SESSION_CACHE_SIZE, SESSION_TIMEOUT, KEY_MANAGERS, TRUST_MANAGERS, providerLoaderDefinition };

        AbstractAddStepHandler add = new TrivialAddHandler<SSLContext>(SSL_CONTEXT_RUNTIME_CAPABILITY, SSLContext.class, attributes) {

            @Override
            protected ValueSupplier<SSLContext> getValueSupplier(ServiceBuilder<SSLContext> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {
                String securityDomain = asStringIfDefined(context, SECURITY_DOMAIN, model);
                String keyManagers = asStringIfDefined(context, KEY_MANAGERS, model);
                String trustManagers = asStringIfDefined(context, TRUST_MANAGERS, model);
                String providerLoaders = asStringIfDefined(context, providerLoaderDefinition, model);

                final List<String> protocols = PROTOCOLS.unwrap(context, model);
                final String cipherSuiteFilter = asStringIfDefined(context, CIPHER_SUITE_FILTER, model);
                final boolean wantClientAuth = WANT_CLIENT_AUTH.resolveModelAttribute(context, model).asBoolean();
                final boolean needClientAuth = NEED_CLIENT_AUTH.resolveModelAttribute(context, model).asBoolean();
                final boolean authenticationOptional = AUTHENTICATION_OPTIONAL.resolveModelAttribute(context, model).asBoolean();
                final int maximumSessionCacheSize = MAXIMUM_SESSION_CACHE_SIZE.resolveModelAttribute(context, model).asInt();
                final int sessionTimeout = SESSION_TIMEOUT.resolveModelAttribute(context, model).asInt();

                final InjectedValue<SecurityDomain> securityDomainInjector = new InjectedValue<>();
                final InjectedValue<KeyManager[]> keyManagersInjector = new InjectedValue<>();
                final InjectedValue<TrustManager[]> trustManagersInjector = new InjectedValue<>();
                final InjectedValue<Provider[]> providersInjector = new InjectedValue<>();

                if (securityDomain != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(SECURITY_DOMAIN_CAPABILITY, securityDomain), SecurityDomain.class),
                            SecurityDomain.class, securityDomainInjector);
                }

                if (keyManagers != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(KEY_MANAGERS_CAPABILITY, keyManagers), KeyManager[].class),
                            KeyManager[].class, keyManagersInjector);
                }

                if (trustManagers != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(TRUST_MANAGERS_CAPABILITY, trustManagers), TrustManager[].class),
                            TrustManager[].class, trustManagersInjector);
                }

                if (providerLoaders != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(PROVIDERS_CAPABILITY, providerLoaders), Provider[].class),
                            Provider[].class, providersInjector);
                }

                return () -> {
                    SecurityDomain securityDomainRef = securityDomainInjector.getOptionalValue();
                    X509ExtendedKeyManager keyManager = getX509KeyManager(keyManagersInjector.getOptionalValue());
                    X509ExtendedTrustManager trustManager = getX509TrustManager(trustManagersInjector.getOptionalValue());
                    Provider[] providersRef = providersInjector.getOptionalValue();

                    ServerSSLContextBuilder builder = new ServerSSLContextBuilder();
                    if (securityDomainRef != null) {
                        builder.setSecurityDomain(securityDomainRef);
                    }
                    if (keyManager != null) {
                        builder.setKeyManager(keyManager);
                    }
                    if (trustManager != null) {
                        builder.setTrustManager(trustManager);
                    }
                    if (providersRef != null) {
                        builder.setProviderSupplier(() -> providersRef);
                    }

                    if (cipherSuiteFilter != null) {
                        builder.setCipherSuiteSelector(CipherSuiteSelector.fromString(cipherSuiteFilter));
                    }

                    if (protocols.isEmpty() == false) {
                        builder.setProtocolSelector(ProtocolSelector.empty()
                                .add(EnumSet.copyOf(protocols.stream().map(Protocol::valueOf).collect(Collectors.toList()))));
                    }

                    builder.setWantClientAuth(wantClientAuth)
                        .setNeedClientAuth(needClientAuth)
                        .setAuthenticationOptional(authenticationOptional)
                        .setSessionCacheSize(maximumSessionCacheSize)
                        .setSessionTimeout(sessionTimeout);

                    try {
                        return builder.build().create();
                    } catch (GeneralSecurityException e) {
                        throw new StartException(e);
                    }
                };

            }

            @Override
            protected void installedForResource(ServiceController<SSLContext> serviceController, Resource resource) {
                assert resource instanceof SSLContextResource;
                ((SSLContextResource)resource).setSSLContextServiceController(serviceController);
            }

            @Override
            protected Resource createResource(OperationContext context) {
                SSLContextResource resource = new SSLContextResource(Resource.Factory.create());
                context.addResource(PathAddress.EMPTY_ADDRESS, resource);

                return resource;
            }

        };

        return new TrivialResourceDefinition<SSLContext>(ElytronDescriptionConstants.SERVER_SSL_CONTEXT, SSL_CONTEXT_RUNTIME_CAPABILITY, SSLContext.class, add, attributes) {

            @Override
            public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
                super.registerAttributes(resourceRegistration);

                resourceRegistration.registerReadOnlyAttribute(ACTIVE_SESSION_COUNT, new SSLContextRuntimeHandler() {

                    @Override
                    protected void performRuntime(ModelNode result, ModelNode operation, SSLContext sslContext) throws OperationFailedException {
                        result.set(Collections.list(sslContext.getServerSessionContext().getIds()).stream().mapToInt( (byte[] b)-> 1).sum());
                    }
                });
            }

            @Override
            public void registerChildren(ManagementResourceRegistration resourceRegistration) {
                super.registerChildren(resourceRegistration);

                resourceRegistration.registerSubModel(new SSLSessionDefinition());
            }

        };
    }

    private static X509ExtendedKeyManager getX509KeyManager(KeyManager[] keyManagers) throws StartException {
        if (keyManagers == null) {
            return null;
        }

        for (KeyManager current : keyManagers) {
            if (current instanceof X509ExtendedKeyManager) {
                return (X509ExtendedKeyManager) current;
            }
        }

        throw ROOT_LOGGER.noTypeFound(X509ExtendedKeyManager.class.getSimpleName());
    }

    private static X509ExtendedTrustManager getX509TrustManager(TrustManager[] trustManagers) throws StartException {
        if (trustManagers == null) {
            return null;
        }

        for (TrustManager current : trustManagers) {
            if (current instanceof X509ExtendedTrustManager) {
                return (X509ExtendedTrustManager) current;
            }
        }

        throw ROOT_LOGGER.noTypeFound(X509ExtendedTrustManager.class.getSimpleName());
    }

    private static SimpleAttributeDefinition setCapabilityReference(String referencedCapability, String dependentCapability, SimpleAttributeDefinition attribute) {
        return new SimpleAttributeDefinitionBuilder(attribute)
                .setCapabilityReference(referencedCapability, dependentCapability, true)
                .build();
    }

    abstract static class SSLContextRuntimeHandler extends AbstractRuntimeOnlyHandler {

        @Override
        protected void executeRuntimeStep(OperationContext context, ModelNode operation) throws OperationFailedException {
            ServiceName serverSSLContextName = SERVER_SSL_CONTEXT.serviceName(operation);

            ServiceController<SSLContext> serviceContainer = getRequiredService(context.getServiceRegistry(false), serverSSLContextName, SSLContext.class);
            State serviceState;
            if ((serviceState = serviceContainer.getState()) != State.UP) {
                    throw ROOT_LOGGER.requiredServiceNotUp(serverSSLContextName, serviceState);
            }

            performRuntime(context.getResult(), operation, serviceContainer.getService().getValue());
        }

        protected abstract void performRuntime(ModelNode result, ModelNode operation, SSLContext sslContext) throws OperationFailedException;
    }

}
