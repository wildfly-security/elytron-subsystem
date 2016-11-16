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
import static org.jboss.as.controller.security.CredentialReference.credentialReferencePartAsStringIfDefined;
import static org.wildfly.extension.elytron.Capabilities.CREDENTIAL_STORE_CLIENT_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.CREDENTIAL_STORE_CLIENT_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.KEY_MANAGERS_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.KEY_MANAGERS_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.KEY_STORE_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.PROVIDERS_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SSL_CONTEXT_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SSL_CONTEXT_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.TRUST_MANAGERS_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.TRUST_MANAGERS_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.ElytronExtension.getRequiredService;
import static org.wildfly.extension.elytron.KeyStoreDefinition.CREDENTIAL_REFERENCE;
import static org.wildfly.extension.elytron.KeyStoreDefinition.CREDENTIAL_STORE_CLIENT_SERVICE_UTIL;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AbstractRuntimeOnlyHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.logging.ControllerLogger;
import org.jboss.as.controller.operations.validation.AllowedValuesValidator;
import org.jboss.as.controller.operations.validation.ModelTypeValidator;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.controller.security.CredentialReference;
import org.jboss.as.controller.security.CredentialStoreClient;
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
import org.wildfly.security.ssl.SSLContextBuilder;

/**
 * Definitions for resources used to configure SSLContexts.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SSLDefinitions {

    static final ServiceUtil<SSLContext> SERVER_SERVICE_UTIL = ServiceUtil.newInstance(SSL_CONTEXT_RUNTIME_CAPABILITY, ElytronDescriptionConstants.SERVER_SSL_CONTEXT, SSLContext.class);
    static final ServiceUtil<SSLContext> CLIENT_SERVICE_UTIL = ServiceUtil.newInstance(SSL_CONTEXT_RUNTIME_CAPABILITY, ElytronDescriptionConstants.CLIENT_SSL_CONTEXT, SSLContext.class);

    static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ALGORITHM, ModelType.STRING, false)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition PROVIDER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PROVIDER, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition PROVIDER_LOADER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PROVIDER_LOADER, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition KEYSTORE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.KEY_STORE, ModelType.STRING, false)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition SECURITY_DOMAIN = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SECURITY_DOMAIN, ModelType.STRING, true)
            .setMinSize(1)
            .setCapabilityReference(SECURITY_DOMAIN_CAPABILITY, SSL_CONTEXT_CAPABILITY, true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition CIPHER_SUITE_FILTER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CIPHER_SUITE_FILTER, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final String[] ALLOWED_PROTOCOLS = { "SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" };

    static final StringListAttributeDefinition PROTOCOLS = new StringListAttributeDefinition.Builder(ElytronDescriptionConstants.PROTOCOLS)
            .setAllowExpression(true)
            .setMinSize(1)
            .setAllowNull(true)
            .setAllowedValues(ALLOWED_PROTOCOLS)
            .setValidator(new StringValuesValidator(ALLOWED_PROTOCOLS))
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

    static final SimpleAttributeDefinition USE_CIPHER_SUITES_ORDER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.USE_CIPHER_SUITES_ORDER, ModelType.BOOLEAN, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(true))
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
            .setMinSize(1)
            .setCapabilityReference(KEY_MANAGERS_CAPABILITY, SSL_CONTEXT_CAPABILITY, true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition TRUST_MANAGERS = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.TRUST_MANAGERS, ModelType.STRING, true)
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

    /**
     * A simple {@link ModelTypeValidator} that requires that values are contained on a pre-defined list of string.
     *
     * //TODO: couldn't find a built-in validator for that. see if there is one or even if it can be moved to its own file.
     */
    static class StringValuesValidator extends ModelTypeValidator implements AllowedValuesValidator {

        private List<ModelNode> allowedValues = new ArrayList<>();

        StringValuesValidator(String... values) {
            super(ModelType.STRING);
            for (String value : values) {
                allowedValues.add(new ModelNode().set(value));
            }
        }

        @Override
        public void validateParameter(String parameterName, ModelNode value) throws OperationFailedException {
            super.validateParameter(parameterName, value);
            if (value.isDefined()) {
                if (!allowedValues.contains(value)) {
                    throw new OperationFailedException(ControllerLogger.ROOT_LOGGER.invalidValue(value.asString(), parameterName, allowedValues));
                }
            }
        }

        @Override
        public List<ModelNode> getAllowedValues() {
            return this.allowedValues;
        }
    }


    static ResourceDefinition getKeyManagerDefinition() {

        final SimpleAttributeDefinition providerLoaderDefinition = new SimpleAttributeDefinitionBuilder(PROVIDER_LOADER)
                .setCapabilityReference(PROVIDERS_CAPABILITY, KEY_MANAGERS_CAPABILITY, true)
                .build();

        final SimpleAttributeDefinition keystoreDefinition = new SimpleAttributeDefinitionBuilder(KEYSTORE)
                .setCapabilityReference(KEY_STORE_CAPABILITY, KEY_MANAGERS_CAPABILITY, true)
                .build();

        final ObjectTypeAttributeDefinition credentialReference = CredentialReference.getAttributeDefinition();

        AttributeDefinition[] attributes = new AttributeDefinition[] { ALGORITHM, providerLoaderDefinition, PROVIDER, keystoreDefinition, credentialReference};

        AbstractAddStepHandler add = new TrivialAddHandler<KeyManager[]>(KeyManager[].class, attributes, KEY_MANAGERS_RUNTIME_CAPABILITY, CREDENTIAL_STORE_CLIENT_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<KeyManager[]> getValueSupplier(ServiceBuilder<KeyManager[]> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {
                final String algorithm = ALGORITHM.resolveModelAttribute(context, model).asString();
                final String provider = PROVIDER.resolveModelAttribute(context, model).isDefined() ? PROVIDER.resolveModelAttribute(context, model).asString() : null;

                String providerLoader = asStringIfDefined(context, providerLoaderDefinition, model);
                final InjectedValue<Provider[]> providersInjector = new InjectedValue<>();
                if (providerLoader != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(PROVIDERS_CAPABILITY, providerLoader), Provider[].class),
                            Provider[].class, providersInjector);
                }

                final String keyStoreName = asStringIfDefined(context, keystoreDefinition, model);
                final InjectedValue<KeyStore> keyStoreInjector = new InjectedValue<>();
                if (keyStoreName != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(KEY_STORE_CAPABILITY, keyStoreName), KeyStore.class),
                            KeyStore.class, keyStoreInjector);
                }

                String credentialStoreName = credentialReferencePartAsStringIfDefined(context, CREDENTIAL_REFERENCE, model, CredentialReference.STORE);
                String credentialAlias = credentialReferencePartAsStringIfDefined(context, CREDENTIAL_REFERENCE, model, CredentialReference.ALIAS);
                String credentialType = credentialReferencePartAsStringIfDefined(context, CREDENTIAL_REFERENCE, model, CredentialReference.TYPE);
                String secret = credentialReferencePartAsStringIfDefined(context, CREDENTIAL_REFERENCE, model, CredentialReference.CLEAR_TEXT);

                final CredentialReference credentialReference;
                if (credentialStoreName != null && !credentialStoreName.isEmpty()) {
                    credentialReference = CredentialReference.createCredentialReference(credentialStoreName, credentialAlias, credentialType);
                } else {
                    credentialReference = CredentialReference.createCredentialReference(secret != null ? secret.toCharArray() : null);
                }

                final InjectedValue<CredentialStoreClient> credentialStoreClientInjector = new InjectedValue<>();
                if (credentialReference.getAlias() != null) {
                    String credentialStoreClientCapabilityName = RuntimeCapability.buildDynamicCapabilityName(CREDENTIAL_STORE_CLIENT_CAPABILITY, credentialReference.getCredentialStoreName());
                    ServiceName credentialStoreClientServiceName = context.getCapabilityServiceName(credentialStoreClientCapabilityName, CredentialStoreClient.class);
                    CREDENTIAL_STORE_CLIENT_SERVICE_UTIL.addInjection(serviceBuilder, credentialStoreClientInjector, credentialStoreClientServiceName);
                }

                return () -> {
                    Provider[] providers = providersInjector.getOptionalValue();
                    KeyManagerFactory keyManagerFactory = null;
                    if (providers != null) {
                        for (Provider current : providers) {
                            if (provider == null || provider.equals(current.getName())) {
                                try {
                                    // TODO - We could check the Services within each Provider to check there is one of the required type/algorithm
                                    // However the same loop would need to remain as it is still possible a specific provider can't create it.
                                    keyManagerFactory = KeyManagerFactory.getInstance(algorithm, current);
                                    break;
                                } catch (NoSuchAlgorithmException ignored) {
                                }
                            }
                        }
                        if (keyManagerFactory == null) throw ROOT_LOGGER.unableToCreateManagerFactory(KeyManagerFactory.class.getSimpleName(), algorithm);
                    } else {
                        try {
                            keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
                        } catch (NoSuchAlgorithmException e) {
                            throw new StartException(e);
                        }
                    }

                    try {
                        CredentialReference.reinjectCredentialStoreClient(credentialStoreClientInjector, credentialReference);
                        CredentialStoreClient credentialStoreClient = credentialStoreClientInjector.getOptionalValue();
                        KeyStore keyStore = keyStoreInjector.getOptionalValue();
                        char[] password = credentialStoreClient != null ? credentialStoreClient.getSecret() : credentialReference.getSecret();

                        if (ROOT_LOGGER.isTraceEnabled()) {
                            ROOT_LOGGER.tracef(
                                    "KeyManager supplying:  providers = %s  provider = %s  algorithm = %s  keyManagerFactory = %s  " +
                                            "keyStoreName = %s  keyStore = %s  password (of item) = %b",
                                    Arrays.toString(providers), provider, algorithm, keyManagerFactory, keyStoreName, keyStore, password != null
                            );
                        }

                        keyManagerFactory.init(keyStore, password);
                    } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | ClassNotFoundException e) {
                        throw new StartException(e);
                    }

                    return keyManagerFactory.getKeyManagers();
                };
            }
        };

        return new TrivialResourceDefinition(ElytronDescriptionConstants.KEY_MANAGERS, add, attributes, KEY_MANAGERS_RUNTIME_CAPABILITY);

    }

    static ResourceDefinition getTrustManagerDefinition() {

        final SimpleAttributeDefinition providerLoaderDefinition = new SimpleAttributeDefinitionBuilder(PROVIDER_LOADER)
                .setCapabilityReference(PROVIDERS_CAPABILITY, TRUST_MANAGERS_CAPABILITY, true)
                .build();

        final SimpleAttributeDefinition keystoreDefinition = new SimpleAttributeDefinitionBuilder(KEYSTORE)
                .setCapabilityReference(KEY_STORE_CAPABILITY, TRUST_MANAGERS_CAPABILITY, true)
                .build();

        AttributeDefinition[] attributes = new AttributeDefinition[] { ALGORITHM, providerLoaderDefinition, PROVIDER, keystoreDefinition};

        AbstractAddStepHandler add = new TrivialAddHandler<TrustManager[]>(TrustManager[].class, attributes, TRUST_MANAGERS_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<TrustManager[]> getValueSupplier(ServiceBuilder<TrustManager[]> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {
                final String algorithm = ALGORITHM.resolveModelAttribute(context, model).asString();
                final String provider = PROVIDER.resolveModelAttribute(context, model).isDefined() ? PROVIDER.resolveModelAttribute(context, model).asString() : null;

                String providerLoader = asStringIfDefined(context, providerLoaderDefinition, model);
                final InjectedValue<Provider[]> providersInjector = new InjectedValue<>();
                if (providerLoader != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(PROVIDERS_CAPABILITY, providerLoader), Provider[].class),
                            Provider[].class, providersInjector);
                }

                final String keyStoreName = asStringIfDefined(context, keystoreDefinition, model);
                final InjectedValue<KeyStore> keyStoreInjector = new InjectedValue<>();
                if (keyStoreName != null) {
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(KEY_STORE_CAPABILITY, keyStoreName), KeyStore.class),
                            KeyStore.class, keyStoreInjector);
                }

                return () -> {
                    Provider[] providers = providersInjector.getOptionalValue();
                    TrustManagerFactory trustManagerFactory = null;

                    if (providers != null) {
                        for (Provider current : providers) {
                            if (provider == null || provider.equals(current.getName())) {
                                try {
                                    // TODO - We could check the Services within each Provider to check there is one of the required type/algorithm
                                    // However the same loop would need to remain as it is still possible a specific provider can't create it.
                                    trustManagerFactory = TrustManagerFactory.getInstance(algorithm, current);
                                    break;
                                } catch (NoSuchAlgorithmException ignored) {
                                }
                            }
                        }
                        if (trustManagerFactory == null) throw ROOT_LOGGER.unableToCreateManagerFactory(TrustManagerFactory.class.getSimpleName(), algorithm);
                    } else {
                        try {
                            trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
                        } catch (NoSuchAlgorithmException e) {
                            throw new StartException(e);
                        }
                    }
                    KeyStore keyStore = keyStoreInjector.getOptionalValue();

                    if (ROOT_LOGGER.isTraceEnabled()) {
                        ROOT_LOGGER.tracef(
                                "KeyManager supplying:  providers = %s  provider = %s  algorithm = %s  trustManagerFactory = %s  keyStoreName = %s  keyStore = %s",
                                Arrays.toString(providers), provider, algorithm, trustManagerFactory, keyStoreName, keyStore
                        );
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

        return new TrivialResourceDefinition(ElytronDescriptionConstants.TRUST_MANAGERS, add, attributes, TRUST_MANAGERS_RUNTIME_CAPABILITY, CREDENTIAL_STORE_CLIENT_RUNTIME_CAPABILITY);
    }

    private static class SSLContextDefinition extends TrivialResourceDefinition {
        final boolean server;

        private SSLContextDefinition(String pathKey, boolean server, AbstractAddStepHandler addHandler, AttributeDefinition[] attributes) {
            super(pathKey, addHandler, attributes, SSL_CONTEXT_RUNTIME_CAPABILITY);
            this.server = server;
        }

        @Override
        public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
            super.registerAttributes(resourceRegistration);

            resourceRegistration.registerReadOnlyAttribute(ACTIVE_SESSION_COUNT, new SSLContextRuntimeHandler() {
                @Override
                protected void performRuntime(ModelNode result, ModelNode operation, SSLContext sslContext) throws OperationFailedException {
                    SSLSessionContext sessionContext = server ? sslContext.getServerSessionContext() : sslContext.getClientSessionContext();
                    result.set(Collections.list(sessionContext.getIds()).stream().mapToInt( (byte[] b)-> 1).sum());
                }

                @Override
                protected ServiceUtil<SSLContext> getSSLContextServiceUtil() {
                    return server ? SERVER_SERVICE_UTIL : CLIENT_SERVICE_UTIL;
                }
            });
        }

        @Override
        public void registerChildren(ManagementResourceRegistration resourceRegistration) {
            super.registerChildren(resourceRegistration);

            resourceRegistration.registerSubModel(new SSLSessionDefinition(server));
        }
    }

    private static <T> InjectedValue<T> addDependency(String baseName, SimpleAttributeDefinition attribute,
            Class<T> type, ServiceBuilder<SSLContext> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {

        String dynamicNameElement = asStringIfDefined(context, attribute, model);
        InjectedValue<T> injectedValue = new InjectedValue<>();

        if (dynamicNameElement != null) {
            serviceBuilder.addDependency(context.getCapabilityServiceName(
                    buildDynamicCapabilityName(baseName, dynamicNameElement), type),
                    type, injectedValue);
        }
        return injectedValue;
    }

    static ResourceDefinition getServerSSLContextDefinition() {

        final SimpleAttributeDefinition providerLoaderDefinition = new SimpleAttributeDefinitionBuilder(PROVIDER_LOADER)
                .setCapabilityReference(PROVIDERS_CAPABILITY, SSL_CONTEXT_CAPABILITY, true)
                .build();

        AttributeDefinition[] attributes = new AttributeDefinition[] { SECURITY_DOMAIN, CIPHER_SUITE_FILTER, PROTOCOLS, WANT_CLIENT_AUTH, NEED_CLIENT_AUTH, AUTHENTICATION_OPTIONAL,
                USE_CIPHER_SUITES_ORDER, MAXIMUM_SESSION_CACHE_SIZE, SESSION_TIMEOUT, KEY_MANAGERS, TRUST_MANAGERS, providerLoaderDefinition };

        return new SSLContextDefinition(ElytronDescriptionConstants.SERVER_SSL_CONTEXT, true, new TrivialAddHandler<SSLContext>(SSLContext.class, attributes, SSL_CONTEXT_RUNTIME_CAPABILITY) {
            @Override
            protected ValueSupplier<SSLContext> getValueSupplier(ServiceBuilder<SSLContext> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {

                final InjectedValue<SecurityDomain> securityDomainInjector = addDependency(SECURITY_DOMAIN_CAPABILITY, SECURITY_DOMAIN, SecurityDomain.class, serviceBuilder, context, model);
                final InjectedValue<KeyManager[]> keyManagersInjector = addDependency(KEY_MANAGERS_CAPABILITY, KEY_MANAGERS, KeyManager[].class, serviceBuilder, context, model);
                final InjectedValue<TrustManager[]> trustManagersInjector = addDependency(TRUST_MANAGERS_CAPABILITY, TRUST_MANAGERS, TrustManager[].class, serviceBuilder, context, model);
                final InjectedValue<Provider[]> providersInjector = addDependency(PROVIDERS_CAPABILITY, providerLoaderDefinition, Provider[].class, serviceBuilder, context, model);

                final List<String> protocols = PROTOCOLS.unwrap(context, model);
                final String cipherSuiteFilter = asStringIfDefined(context, CIPHER_SUITE_FILTER, model);
                final boolean wantClientAuth = WANT_CLIENT_AUTH.resolveModelAttribute(context, model).asBoolean();
                final boolean needClientAuth = NEED_CLIENT_AUTH.resolveModelAttribute(context, model).asBoolean();
                final boolean authenticationOptional = AUTHENTICATION_OPTIONAL.resolveModelAttribute(context, model).asBoolean();
                final boolean useCipherSuitesOrder = USE_CIPHER_SUITES_ORDER.resolveModelAttribute(context, model).asBoolean();
                final int maximumSessionCacheSize = MAXIMUM_SESSION_CACHE_SIZE.resolveModelAttribute(context, model).asInt();
                final int sessionTimeout = SESSION_TIMEOUT.resolveModelAttribute(context, model).asInt();

                return () -> {
                    SecurityDomain securityDomain = securityDomainInjector.getOptionalValue();
                    X509ExtendedKeyManager keyManager = getX509KeyManager(keyManagersInjector.getOptionalValue());
                    X509ExtendedTrustManager trustManager = getX509TrustManager(trustManagersInjector.getOptionalValue());
                    Provider[] providers = providersInjector.getOptionalValue();

                    SSLContextBuilder builder = new SSLContextBuilder();
                    if (securityDomain != null) builder.setSecurityDomain(securityDomain);
                    if (keyManager != null) builder.setKeyManager(keyManager);
                    if (trustManager != null) builder.setTrustManager(trustManager);
                    if (providers != null) builder.setProviderSupplier(() -> providers);
                    if (cipherSuiteFilter != null) builder.setCipherSuiteSelector(CipherSuiteSelector.fromString(cipherSuiteFilter));
                    if ( ! protocols.isEmpty()) builder.setProtocolSelector(ProtocolSelector.empty().add(
                            EnumSet.copyOf(protocols.stream().map(Protocol::forName).collect(Collectors.toList()))
                    ));
                    builder.setWantClientAuth(wantClientAuth)
                           .setNeedClientAuth(needClientAuth)
                           .setAuthenticationOptional(authenticationOptional)
                           .setUseCipherSuitesOrder(useCipherSuitesOrder)
                           .setSessionCacheSize(maximumSessionCacheSize)
                           .setSessionTimeout(sessionTimeout);

                    if (ROOT_LOGGER.isTraceEnabled()) {
                        ROOT_LOGGER.tracef(
                                "ServerSSLContext supplying:  securityDomain = %s  keyManager = %s  trustManager = %s  " +
                                "providers = %s  cipherSuiteFilter = %s  protocols = %s  wantClientAuth = %s  needClientAuth = %s  " +
                                "authenticationOptional = %s  maximumSessionCacheSize = %s  sessionTimeout = %s",
                                securityDomain, keyManager, trustManager, Arrays.toString(providers), cipherSuiteFilter,
                                Arrays.toString(protocols.toArray()), wantClientAuth, needClientAuth, authenticationOptional,
                                maximumSessionCacheSize, sessionTimeout);
                    }

                    try {
                        return builder.build().create();
                    } catch (GeneralSecurityException e) {
                        throw new StartException(e);
                    }
                };
            }

            @Override
            protected Resource createResource(OperationContext context) {
                SSLContextResource resource = new SSLContextResource(Resource.Factory.create(), true);
                context.addResource(PathAddress.EMPTY_ADDRESS, resource);
                return resource;
            }

            @Override
            protected void installedForResource(ServiceController<SSLContext> serviceController, Resource resource) {
                ((SSLContextResource)resource).setSSLContextServiceController(serviceController);
            }
        }, attributes);
    }

    static ResourceDefinition getClientSSLContextDefinition() {

        final SimpleAttributeDefinition providerLoaderDefinition = new SimpleAttributeDefinitionBuilder(PROVIDER_LOADER)
                .setCapabilityReference(PROVIDERS_CAPABILITY, SSL_CONTEXT_CAPABILITY, true)
                .build();

        AttributeDefinition[] attributes = new AttributeDefinition[] { CIPHER_SUITE_FILTER, PROTOCOLS,
                USE_CIPHER_SUITES_ORDER, MAXIMUM_SESSION_CACHE_SIZE, SESSION_TIMEOUT, KEY_MANAGERS, TRUST_MANAGERS, providerLoaderDefinition };

        return new SSLContextDefinition(ElytronDescriptionConstants.CLIENT_SSL_CONTEXT, false, new TrivialAddHandler<SSLContext>(SSLContext.class, attributes, SSL_CONTEXT_RUNTIME_CAPABILITY) {
            @Override
            protected ValueSupplier<SSLContext> getValueSupplier(ServiceBuilder<SSLContext> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {

                final InjectedValue<KeyManager[]> keyManagersInjector = addDependency(KEY_MANAGERS_CAPABILITY, KEY_MANAGERS, KeyManager[].class, serviceBuilder, context, model);
                final InjectedValue<TrustManager[]> trustManagersInjector = addDependency(TRUST_MANAGERS_CAPABILITY, TRUST_MANAGERS, TrustManager[].class, serviceBuilder, context, model);
                final InjectedValue<Provider[]> providersInjector = addDependency(PROVIDERS_CAPABILITY, providerLoaderDefinition, Provider[].class, serviceBuilder, context, model);

                final List<String> protocols = PROTOCOLS.unwrap(context, model);
                final String cipherSuiteFilter = asStringIfDefined(context, CIPHER_SUITE_FILTER, model);
                final boolean useCipherSuitesOrder = USE_CIPHER_SUITES_ORDER.resolveModelAttribute(context, model).asBoolean();
                final int maximumSessionCacheSize = MAXIMUM_SESSION_CACHE_SIZE.resolveModelAttribute(context, model).asInt();
                final int sessionTimeout = SESSION_TIMEOUT.resolveModelAttribute(context, model).asInt();

                return () -> {
                    X509ExtendedKeyManager keyManager = getX509KeyManager(keyManagersInjector.getOptionalValue());
                    X509ExtendedTrustManager trustManager = getX509TrustManager(trustManagersInjector.getOptionalValue());
                    Provider[] providers = providersInjector.getOptionalValue();

                    SSLContextBuilder builder = new SSLContextBuilder();
                    if (keyManager != null) builder.setKeyManager(keyManager);
                    if (trustManager != null) builder.setTrustManager(trustManager);
                    if (providers != null) builder.setProviderSupplier(() -> providers);
                    if (cipherSuiteFilter != null) builder.setCipherSuiteSelector(CipherSuiteSelector.fromString(cipherSuiteFilter));
                    if ( ! protocols.isEmpty()) builder.setProtocolSelector(ProtocolSelector.empty().add(
                            EnumSet.copyOf(protocols.stream().map(Protocol::forName).collect(Collectors.toList()))
                    ));
                    builder.setClientMode(true)
                           .setUseCipherSuitesOrder(useCipherSuitesOrder)
                           .setSessionCacheSize(maximumSessionCacheSize)
                           .setSessionTimeout(sessionTimeout);

                    if (ROOT_LOGGER.isTraceEnabled()) {
                        ROOT_LOGGER.tracef(
                                "ClientSSLContext supplying:  keyManager = %s  trustManager = %s  providers = %s  " +
                                "cipherSuiteFilter = %s  protocols = %s  maximumSessionCacheSize = %s  sessionTimeout = %s",
                                keyManager, trustManager, Arrays.toString(providers), cipherSuiteFilter,
                                Arrays.toString(protocols.toArray()), maximumSessionCacheSize, sessionTimeout
                        );
                    }

                    try {
                        return builder.build().create();
                    } catch (GeneralSecurityException e) {
                        throw new StartException(e);
                    }
                };
            }

            @Override
            protected Resource createResource(OperationContext context) {
                SSLContextResource resource = new SSLContextResource(Resource.Factory.create(), false);
                context.addResource(PathAddress.EMPTY_ADDRESS, resource);
                return resource;
            }

            @Override
            protected void installedForResource(ServiceController<SSLContext> serviceController, Resource resource) {
                ((SSLContextResource)resource).setSSLContextServiceController(serviceController);
            }
        }, attributes);
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

    abstract static class SSLContextRuntimeHandler extends AbstractRuntimeOnlyHandler {
        @Override
        protected void executeRuntimeStep(OperationContext context, ModelNode operation) throws OperationFailedException {
            ServiceName serviceName = getSSLContextServiceUtil().serviceName(operation);

            ServiceController<SSLContext> serviceController = getRequiredService(context.getServiceRegistry(false), serviceName, SSLContext.class);
            State serviceState;
            if ((serviceState = serviceController.getState()) != State.UP) {
                    throw ROOT_LOGGER.requiredServiceNotUp(serviceName, serviceState);
            }

            performRuntime(context.getResult(), operation, serviceController.getService().getValue());
        }

        protected abstract void performRuntime(ModelNode result, ModelNode operation, SSLContext sslContext) throws OperationFailedException;

        protected abstract ServiceUtil<SSLContext> getSSLContextServiceUtil();
    }

}
