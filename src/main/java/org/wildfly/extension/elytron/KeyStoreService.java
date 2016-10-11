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

import static org.wildfly.extension.elytron.FileAttributeDefinitions.pathResolver;
import static org.wildfly.extension.elytron.ProviderUtil.identifyProvider;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.security.CredentialReference;
import org.jboss.as.controller.security.CredentialStoreClient;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.FileAttributeDefinitions.PathResolver;
import org.wildfly.security.keystore.AliasFilter;
import org.wildfly.security.keystore.AtomicLoadKeyStore;
import org.wildfly.security.keystore.FilteringKeyStore;
import org.wildfly.security.keystore.ModifyTrackingKeyStore;
import org.wildfly.security.keystore.UnmodifiableKeyStore;

/**
 * A {@link Service} responsible for a single {@link KeyStore} instance.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class KeyStoreService implements ModifiableKeyStoreService {

    private final String provider;
    private final String type;
    private final String path;
    private final String relativeTo;
    private final boolean required;
    private final String aliasFilter;
    private final CredentialReference credentialReference;

    private final InjectedValue<PathManager> pathManager = new InjectedValue<>();
    private final InjectedValue<Provider[]> providers = new InjectedValue<>();
    private final InjectedValue<CredentialStoreClient> injectedCredentialStoreClient = new InjectedValue<>();

    private PathResolver pathResolver;
    private File resolvedPath;

    private volatile long synched;
    private volatile AtomicLoadKeyStore keyStore = null;
    private volatile ModifyTrackingKeyStore trackingKeyStore = null;
    private volatile KeyStore unmodifiableKeyStore = null;

    private KeyStoreService(String provider, String type, String relativeTo, String path, boolean required, String aliasFilter, CredentialReference credentialReference) {
        this.provider = provider;
        this.type = type;
        this.relativeTo = relativeTo;
        this.path = path;
        this.required = required;
        this.aliasFilter = aliasFilter;
        this.credentialReference = credentialReference;
    }

    static KeyStoreService createFileLessKeyStoreService(String provider, String type, String aliasFilter, CredentialReference credentialReference) {
        return new KeyStoreService(provider, type, null, null, false, aliasFilter, credentialReference);
    }

    static KeyStoreService createFileBasedKeyStoreService(String provider, String type, String relativeTo, String path, boolean required, String aliasFilter, CredentialReference credentialReference) {
        return new KeyStoreService(provider, type, relativeTo, path, required, aliasFilter, credentialReference);
    }

    /*
     * Service Lifecycle Related Methods
     */

    @Override
    public void start(StartContext startContext) throws StartException {
        try {
            AtomicLoadKeyStore keyStore = AtomicLoadKeyStore.newInstance(type, resolveProvider());
            if (path != null) {
                pathResolver = pathResolver();
                pathResolver.path(path);
                if (relativeTo != null) {
                    pathResolver.relativeTo(relativeTo, pathManager.getValue());
                }
                resolvedPath = pathResolver.resolve();
            }

            try {
                CredentialReference.reinjectCredentialStoreClient(injectedCredentialStoreClient, credentialReference);
            } catch (ClassNotFoundException e) {
                throw ROOT_LOGGER.unableToStartService(e);
            }

            synched = System.currentTimeMillis();
            try (InputStream is = resolvedPath != null ? new FileInputStream(resolvedPath) : null) {
                keyStore.load(is, resolvePassword());
            }

            this.keyStore = keyStore;
            KeyStore intermediate = aliasFilter != null ? FilteringKeyStore.filteringKeyStore(keyStore, AliasFilter.fromString(aliasFilter)) :  keyStore;
            this.trackingKeyStore = ModifyTrackingKeyStore.modifyTrackingKeyStore(intermediate);
            this.unmodifiableKeyStore = UnmodifiableKeyStore.unmodifiableKeyStore(intermediate);
        } catch (GeneralSecurityException | IOException e) {
            throw ROOT_LOGGER.unableToStartService(e);
        }
    }

    private Provider resolveProvider() throws StartException {
        Provider[] candidates = providers.getOptionalValue();
        Provider identified = identifyProvider(candidates == null ? Security.getProviders() : candidates, provider, KeyStore.class, type);
        if (identified == null) {
            throw ROOT_LOGGER.noSuitableProvider(type);
        }
        return identified;
    }

    private AtomicLoadKeyStore.LoadKey load(AtomicLoadKeyStore keyStore) throws GeneralSecurityException, IOException {
        try (InputStream is = resolvedPath != null ? new FileInputStream(resolvedPath) : null) {
            return keyStore.revertibleLoad(is, resolvePassword());
        }
    }

    @Override
    public void stop(StopContext stopContext) {
        keyStore = null;
        if (pathResolver != null) {
            pathResolver.clear();
            pathResolver = null;
        }
    }

    @Override
    public KeyStore getValue() throws IllegalStateException, IllegalArgumentException {
        return unmodifiableKeyStore;
    }

    public KeyStore getModifiableValue() {
        return trackingKeyStore;
    }

    Injector<PathManager> getPathManagerInjector() {
        return pathManager;
    }

    Injector<Provider[]> getProvidersInjector() {
        return providers;
    }

    Injector<CredentialStoreClient> getCredentialStoreClientInjector() {
        return injectedCredentialStoreClient;
    }

    /*
     * OperationStepHandler Access Methods
     */

    long timeSynched() {
        return synched;
    }

    LoadKey load() throws OperationFailedException {
        try {
            AtomicLoadKeyStore.LoadKey loadKey = load(keyStore);
            long originalSynced = synched;
            synched = System.currentTimeMillis();
            boolean originalModified = trackingKeyStore.isModified();
            trackingKeyStore.setModified(false);
            return new LoadKey(loadKey, originalSynced, originalModified);
        } catch (GeneralSecurityException | IOException e) {
            throw ROOT_LOGGER.unableToCompleteOperation(e, e.getLocalizedMessage());
        }
    }

    void revertLoad(final LoadKey loadKey) {
        keyStore.revert(loadKey.loadKey);
        synched = loadKey.modifiedTime;
        trackingKeyStore.setModified(loadKey.modified);
    }

    void save() throws OperationFailedException {
        if (resolvedPath == null) {
            throw ROOT_LOGGER.cantSaveWithoutFile();
        }
        try (FileOutputStream fos = new FileOutputStream(resolvedPath)) {
            keyStore.store(fos, resolvePassword());
            synched = System.currentTimeMillis();
            trackingKeyStore.setModified(false);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw ROOT_LOGGER.unableToCompleteOperation(e, e.getLocalizedMessage());
        }
    }

    boolean isModified() {
        return trackingKeyStore.isModified();
    }

    private char[] resolvePassword() {
        CredentialStoreClient credentialStoreClient = injectedCredentialStoreClient.getValue();
        return credentialStoreClient.getSecret();
    }

    class LoadKey {
        private final AtomicLoadKeyStore.LoadKey loadKey;
        private final long modifiedTime;
        private final boolean modified;

        LoadKey(AtomicLoadKeyStore.LoadKey loadKey, long modifiedTime, boolean modified) {
            this.loadKey = loadKey;
            this.modifiedTime = modifiedTime;
            this.modified = modified;
        }
    }

}
