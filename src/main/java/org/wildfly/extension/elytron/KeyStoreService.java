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

import java.security.KeyStore;

import org.jboss.as.controller.services.path.PathManager;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;

/**
 * A {@link Service} responsible for a single {@link KeyStore} instance.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class KeyStoreService implements Service<KeyStore> {

    private final String provider;
    private final String type;
    private final char[] password;
    private final String path;
    private final String relativeTo;
    private boolean required;
    private boolean watch;

    private final InjectedValue<PathManager> pathManager = new InjectedValue<PathManager>();

    private KeyStore keyStore = null;

    private KeyStoreService(String provider, String type, char[] password, String relativeTo, String path, boolean required, boolean watch) {
        this.provider = provider;
        this.type = type;
        this.password = password != null ? password.clone() : password;
        this.relativeTo = relativeTo;
        this.path = path;
        this.required = required;
        this.watch = watch;
    }

    static KeyStoreService createFileLessKeyStoreService(String provider, String type, char[] password) {
        return new KeyStoreService(provider, type, password, null, null, false, false);
    }

    static KeyStoreService createFileBasedKeyStoreService(String provider, String type, char[] password, String relativeTo, String path, boolean required, boolean watch) {
        return new KeyStoreService(provider, type, password, relativeTo, path, required, watch);
    }

    @Override
    public void start(StartContext startContext) throws StartException {


    }

    @Override
    public void stop(StopContext stopContext) {


    }

    @Override
    public KeyStore getValue() throws IllegalStateException, IllegalArgumentException {
        return keyStore;
    }

    Injector<PathManager> getPathManagerInjector() {
        return pathManager;
    }

}
