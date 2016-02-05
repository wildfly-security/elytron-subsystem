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
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.FileAttributeDefinitions.PathResolver;
import org.wildfly.security.keystore.AtomicLoadKeyStore;
import org.wildfly.security.keystore.ModifyTrackingKeyStore;
import org.wildfly.security.keystore.UnmodifiableKeyStore;

/**
 * A {@link Service} responsible for a single {@link KeyStore} instance.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class KeyStoreService implements Service<KeyStore> {

    private final String provider;
    private final String type;
    private final char[] password;
    private final String path;
    private final String relativeTo;
    private final boolean required;

    private final InjectedValue<PathManager> pathManager = new InjectedValue<PathManager>();
    private final InjectedValue<Provider[]> providers = new InjectedValue<Provider[]>();

    private PathResolver pathResolver;
    private File resolvedPath;

    private volatile long synched;
    private volatile AtomicLoadKeyStore keyStore = null;
    private volatile ModifyTrackingKeyStore trackingKeyStore = null;
    private volatile KeyStore unmodifiableKeyStore = null;

    private KeyStoreService(String provider, String type, char[] password, String relativeTo, String path, boolean required) {
        this.provider = provider;
        this.type = type;
        this.password = password != null ? password.clone() : null;
        this.relativeTo = relativeTo;
        this.path = path;
        this.required = required;
    }

    static KeyStoreService createFileLessKeyStoreService(String provider, String type, char[] password) {
        return new KeyStoreService(provider, type, password, null, null, false);
    }

    static KeyStoreService createFileBasedKeyStoreService(String provider, String type, char[] password, String relativeTo, String path, boolean required) {
        return new KeyStoreService(provider, type, password, relativeTo, path, required);
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

            synched = System.currentTimeMillis();
            try (InputStream is = resolvedPath != null ? new FileInputStream(resolvedPath) : null) {
                keyStore.load(is, password);
            }

            this.keyStore = keyStore;
            this.trackingKeyStore = ModifyTrackingKeyStore.modifyTrackingKeyStore(keyStore);
            this.unmodifiableKeyStore = UnmodifiableKeyStore.unmodifiableKeyStore(keyStore);
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
            return keyStore.revertibleLoad(is, password);
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

    KeyStore getModifiableValue() {
        return trackingKeyStore;
    }

    Injector<PathManager> getPathManagerInjector() {
        return pathManager;
    }

    Injector<Provider[]> getProvidersInjector() {
        return providers;
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
            throw ROOT_LOGGER.unableToCompleteOperation(e);
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
            keyStore.store(fos, password);
            synched = System.currentTimeMillis();
            trackingKeyStore.setModified(false);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw ROOT_LOGGER.unableToCompleteOperation(e);
        }
    }

    boolean isModified() {
        return trackingKeyStore.isModified();
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
