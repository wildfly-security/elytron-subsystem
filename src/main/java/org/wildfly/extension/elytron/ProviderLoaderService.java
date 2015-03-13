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

import static org.wildfly.extension.elytron.SecurityActions.doPrivileged;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;

import org.jboss.modules.Module;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoadException;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;

/**
 * A {@link Service} to return an ordered array of {@link Provider} instances.
 *
 * The order of the {@link Provider} instances will either be the order the class names were specified or will be in
 * {@link ServiceLoader} discovery order.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ProviderLoaderService implements Service<Provider[]> {

    private final boolean register;
    private final ProviderConfig[] providerConfig;

    private volatile Provider[] providers;

    private ProviderLoaderService(final boolean register, final ProviderConfig[] providerConfig) {
        this.register = register;
        this.providerConfig = providerConfig;
    }

    @Override
    public void start(StartContext context) throws StartException {

        try {
            ArrayList<Provider> providerList = new ArrayList<Provider>();
            for (ProviderConfig currentConfig : providerConfig) {
                providerList.addAll(loadProviders(currentConfig));
            }

            Provider[] providers = providerList.toArray(new Provider[providerList.size()]);
            if (register) {
                doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                    registerProviders(providers);
                    return null;
                });
            }

            this.providers = providers;
        } catch (Exception e) {
            if (e instanceof StartException) {
                throw (StartException) e;
            } else if (e.getCause() instanceof StartException) {
                throw (StartException) e.getCause();
            }
            throw ROOT_LOGGER.unableToStartService(e);
        }
    }

    private List<Provider> loadProviders(ProviderConfig config) throws Exception {
        ClassLoader classLoader = doPrivileged((PrivilegedExceptionAction<ClassLoader>) () -> resolveClassLoader(config));
        ArrayList<Provider> providers = new ArrayList<Provider>();
        Set<String> discovered = new HashSet<String>();

        if (config.loadServices()) {
            ServiceLoader<Provider> loader = ServiceLoader.load(Provider.class, classLoader);
            loader.iterator().forEachRemaining((Provider p) -> {
                providers.add(p);
                discovered.add(p.getClass().getName());
            });
        }

        for (String className : config.getClassNames()) {
            if (discovered.contains(className) == false) {
                providers.add(((Class<Provider>) classLoader.loadClass(className)).newInstance());
            }
        }

        // TODO - This will be the point to configure the providers.

        return providers;
    }

    private void registerProviders(final Provider[] providers) throws StartException {
        for (int i = 0; i < providers.length; i++) {
            if (Security.addProvider(providers[i]) < 0) {
                for (int j = i - 1; j > 0; j--) {
                    Security.removeProvider(providers[j].getName());
                }
                throw ROOT_LOGGER.providerAlreadyRegisteres(providers[i].getName());
            }
        }
    }

    private ClassLoader resolveClassLoader(ProviderConfig config) throws ModuleLoadException {
        Module current = Module.getCallerModule();
        if (config.getModule() != null) {
            ModuleIdentifier mi = ModuleIdentifier.create(config.getModule(), config.getSlot());
            current = current.getModule(mi);
        }

        return current.getClassLoader();
    }

    @Override
    public void stop(StopContext context) {
        if (register) {
            doPrivileged((PrivilegedAction<Void>) () -> {
                unregisterProviders();
                return null;
            });
        }

        providers = null;
    }

    private void unregisterProviders() {
        for (int i = providers.length - 1; i < 0; i--) {
            Security.removeProvider(providers[i].getName());
        }
    }

    @Override
    public Provider[] getValue() throws IllegalStateException, IllegalArgumentException {
        return providers == null ? null : providers.clone();
    }

    private static class ProviderConfig {

        private final String module;
        private final String slot;
        private final boolean loadServices;
        private final String[] classNames;

        private ProviderConfig(String module, String slot, boolean loadServices, String[] classNames) {
            this.module = module;
            this.slot = slot;
            this.loadServices = loadServices;
            this.classNames = classNames;
        }

        private String getModule() {
            return module;
        }

        private String getSlot() {
            return slot;
        }

        private boolean loadServices() {
            return loadServices;
        }

        private String[] getClassNames() {
            return classNames;
        }
    }

    static ProviderLoaderServiceBuilder builder() {
        return new ProviderLoaderServiceBuilder();
    }

    static class ProviderLoaderServiceBuilder {

        private boolean register = false;
        private ArrayList<ProviderConfig> providerConfig = new ArrayList<ProviderLoaderService.ProviderConfig>();

        private ProviderLoaderServiceBuilder() {
        }

        ProviderLoaderServiceBuilder setRegister(final boolean register) {
            this.register = register;

            return this;
        }

        ProviderConfigBuilder addProviderConfig() {
            return new ProviderConfigBuilder(this);
        }

        private void add(ProviderConfig config) {
            providerConfig.add(config);
        }

        ProviderLoaderService build() {
            return new ProviderLoaderService(register, providerConfig.toArray(new ProviderConfig[providerConfig.size()]));
        }
    }

    static class ProviderConfigBuilder {

        private final ProviderLoaderServiceBuilder serviceBuilder;

        private String module;
        private String slot;
        private boolean loadServices;
        private String[] classNames;

        private ProviderConfigBuilder(ProviderLoaderServiceBuilder serviceBuilder) {
            this.serviceBuilder = serviceBuilder;
        }

        ProviderConfigBuilder setModule(String module) {
            this.module = module;

            return this;
        }

        ProviderConfigBuilder setSlot(String slot) {
            this.slot = slot;

            return this;
        }

        ProviderConfigBuilder setLoadServices(boolean loadServices) {
            this.loadServices = loadServices;

            return this;
        }

        ProviderConfigBuilder setClassNames(final String[] classNames) {
            this.classNames = classNames == null ? new String[0] : classNames.clone();

            return this;
        }

        ProviderLoaderServiceBuilder build() {
            serviceBuilder.add(new ProviderConfig(module, slot, loadServices, classNames));

            return serviceBuilder;
        }
    }

}
