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

import static org.wildfly.security.credential.store.impl.KeystorePasswordStore.KEY_STORE_PASSWORD_STORE;

import java.io.File;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.Map;

import org.jboss.as.controller.security.CredentialStoreClient;
import org.jboss.as.controller.security.CredentialStoreURIParser;
import org.jboss.as.controller.services.path.PathEntry;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.as.controller.services.path.PathManager.Callback.Handle;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron._private.ElytronSubsystemMessages;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * A {@link Service} responsible for a {@link CredentialStore} instance.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
class CredentialStoreService implements Service<CredentialStoreClient> {

    private CredentialStore credentialStore;
    private final String type;
    private final String provider;
    private final String relativeTo;
    private final String name;
    private final Map<String, String> credentialStoreAttributes;

    private final InjectedValue<PathManager> pathManager = new InjectedValue<>();
    private final InjectedValue<Provider[]> providers = new InjectedValue<>();



    private Handle callbackHandle;

    private CredentialStoreService(String name, Map<String, String> credentialStoreAttributes, String type, String provider, String relativeTo) throws CredentialStoreException {
        this.name = name;
        this.type = type != null ? type : KEY_STORE_PASSWORD_STORE;
        this.provider = provider;
        this.relativeTo = relativeTo;
        this.credentialStoreAttributes = credentialStoreAttributes;
    }

    static CredentialStoreService createCredentialStoreService(String name, String uri, String type, String provider, String relativeTo) throws CredentialStoreException {
        try {
            CredentialStoreURIParser vaultURIParser = new CredentialStoreURIParser(uri);
            String nameToSet = name != null ? name : vaultURIParser.getName(); // once we specify name, the name from uri is ignored
            Map<String, String> credentialStoreAttributes = vaultURIParser.getOptionsMap();
            credentialStoreAttributes.put(ElytronDescriptionConstants.CREDENTIAL_STORE_NAME, nameToSet);
            String storageFile = vaultURIParser.getVaultStore();
            if (storageFile != null) {
                credentialStoreAttributes.put(ElytronDescriptionConstants.CREDENTIAL_STORE_FILE, storageFile);
            }
            return new CredentialStoreService(nameToSet, credentialStoreAttributes, type, provider, relativeTo);
        } catch (URISyntaxException e) {
            throw new CredentialStoreException(e);
        }
    }

    /*
     * Service Lifecycle Related Methods
     */

    @Override
    public void start(StartContext startContext) throws StartException {
        resolveFileLocation();
        try {
            credentialStore = provider != null ? CredentialStore.getInstance(type, provider) : CredentialStore.getInstance(type);
            credentialStore.initialize(credentialStoreAttributes);
        } catch (CredentialStoreException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw ElytronSubsystemMessages.ROOT_LOGGER.unableToStartService(e);
        }
    }

    @Override
    public void stop(StopContext stopContext) {
        if (callbackHandle != null) {
            callbackHandle.remove();
        }
    }

    @Override
    public CredentialStoreClient getValue() {
        return new CredentialStoreClient(name, credentialStore);
    }

    private void resolveFileLocation() {
        File baseDir;
        if (relativeTo != null) {
            PathManager pathManager = this.pathManager.getValue();
            baseDir = new File(pathManager.resolveRelativePathEntry("", relativeTo));
            callbackHandle = pathManager.registerCallback(relativeTo, new PathManager.Callback() {

                @Override
                public void pathModelEvent(PathManager.PathEventContext eventContext, String name) {
                    if (eventContext.isResourceServiceRestartAllowed() == false) {
                        eventContext.reloadRequired();
                    }
                }

                @Override
                public void pathEvent(PathManager.Event event, PathEntry pathEntry) {
                    // Service dependencies should trigger a stop and start.
                }
            }, PathManager.Event.REMOVED, PathManager.Event.UPDATED);
        } else {
            baseDir = new File(".");
        }
        if (baseDir != null) {
            credentialStoreAttributes.put(ElytronDescriptionConstants.CREDENTIAL_STORE_BASE, baseDir.getAbsolutePath());
        }
    }

    Injector<Provider[]> getProvidersInjector() {
        return providers;
    }

    Injector<PathManager> getPathManagerInjector() {
        return pathManager;
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public String getProvider() {
        return provider;
    }
}
