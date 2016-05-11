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

import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.resolveClassLoader;
import static org.wildfly.extension.elytron.SecurityActions.doPrivileged;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.function.Supplier;

import org.jboss.as.controller.services.path.PathEntry;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.as.controller.services.path.PathManager.Callback;
import org.jboss.as.controller.services.path.PathManager.Callback.Handle;
import org.jboss.as.controller.services.path.PathManager.Event;
import org.jboss.as.controller.services.path.PathManager.PathEventContext;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;


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

    private final InjectedValue<PathManager> pathManager = new InjectedValue<PathManager>();
    private final List<Handle> callbackHandles = new ArrayList<Handle>();

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
            clearCallbacks();
            if (e instanceof StartException) {
                throw (StartException) e;
            } else if (e.getCause() instanceof StartException) {
                throw (StartException) e.getCause();
            }
            throw ROOT_LOGGER.unableToStartService(e);
        }
    }

    private List<Provider> loadProviders(ProviderConfig config) throws Exception {
        ClassLoader classLoader = doPrivileged((PrivilegedExceptionAction<ClassLoader>) () -> resolveClassLoader(config.getModule()));
        ArrayList<Provider> providers = new ArrayList<Provider>();
        Set<String> discovered = new HashSet<String>();

        if (config.loadServices()) {
            ServiceLoader<Provider> loader = ServiceLoader.load(Provider.class, classLoader);
            loader.iterator().forEachRemaining((Provider p) -> {
                providers.add(p);
                discovered.add(p.getClass().getName());
            });
        }

        final Supplier<InputStream> configurationStreamSupplier = getConfigurationSupplier(config);
        if (configurationStreamSupplier != null) {
            for (Provider p : providers) {
                try (InputStream is = configurationStreamSupplier.get()) {
                    p.load(is);
                }
            }
        }

        for (String className : config.getClassNames()) {
            if (discovered.contains(className) == false) {
                Class<? extends Provider> providerClazz = classLoader.loadClass(className).asSubclass(Provider.class);
                Provider provider = null;
                if (configurationStreamSupplier != null) {
                    Constructor<?>[] constructors = providerClazz.getConstructors();
                    for (Constructor<?> current : constructors) {
                        Class<?>[] parameterTypes = current.getParameterTypes();
                        if (parameterTypes.length == 1 && parameterTypes[0].isAssignableFrom(InputStream.class)) {
                            try (InputStream is = configurationStreamSupplier.get()) {
                                provider = (Provider) current.newInstance(configurationStreamSupplier.get());
                            }
                            break;
                        }
                    }
                }

                if (provider == null) {
                    provider = providerClazz.newInstance();
                    if (configurationStreamSupplier != null) {
                        try (InputStream is = configurationStreamSupplier.get()) {
                            provider.load(configurationStreamSupplier.get());
                        }
                    }
                }

                providers.add(provider);
            }
        }

        return providers;
    }

    private void registerProviders(final Provider[] providers) throws StartException {
        for (int i = 0; i < providers.length; i++) {
            if (Security.addProvider(providers[i]) < 0) {
                for (int j = i - 1; j > 0; j--) {
                    Security.removeProvider(providers[j].getName());
                }
                throw ROOT_LOGGER.providerAlreadyRegistered(providers[i].getName());
            }
        }
    }

    private static InputStream toInputStream(final File file) {
        try {
            SecurityActions.doPrivileged((PrivilegedExceptionAction<InputStream>) () -> new FileInputStream(file) );
            return new FileInputStream(file);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Supplier<InputStream> getConfigurationSupplier(ProviderConfig config) {
        if (config.getPath() != null) {
            final File configFile = resolveFileLocation(config.getPath(), config.getRelativeTo());

            return () -> toInputStream(configFile);
        }

        List<Property> configurationProperties = config.getPropertyList();
        if (configurationProperties != null) {
            StringBuilder sb = new StringBuilder();
            for (Property current : configurationProperties) {
                sb.append(current.getKey()).append('=').append(current.getValue()).append('\n');
            }
            byte[] configBytes = sb.toString().getBytes(StandardCharsets.UTF_8);

            return () -> new ByteArrayInputStream(configBytes);
        }

        return null;
    }

    private File resolveFileLocation(String path, String relativeTo) {
        final File resolvedPath;
        if (relativeTo != null) {
            PathManager pathManager = this.pathManager.getValue();
            resolvedPath = new File(pathManager.resolveRelativePathEntry(path, relativeTo));
            callbackHandles.add(pathManager.registerCallback(relativeTo, new Callback() {

                        @Override
                        public void pathModelEvent(PathEventContext eventContext, String name) {
                            if (eventContext.isResourceServiceRestartAllowed() == false) {
                                eventContext.reloadRequired();
                            }
                        }

                        @Override
                        public void pathEvent(Event event, PathEntry pathEntry) {
                            // Service dependencies should trigger a stop and start.
                        }
                    }, Event.REMOVED, Event.UPDATED));
        } else {
            resolvedPath = new File(path);
        }

        return resolvedPath;
    }

    private void clearCallbacks() {
        while(callbackHandles.isEmpty() == false) {
            callbackHandles.remove(0).remove();
        }
    }

    @Override
    public void stop(StopContext context) {
        if (register) {
            doPrivileged((PrivilegedAction<Void>) () -> {
                unregisterProviders();
                return null;
            });
        }

        clearCallbacks();

        providers = null;
    }

    private void unregisterProviders() {
        for (int i = providers.length - 1; i < 0; i--) {
            Security.removeProvider(providers[i].getName());
        }
    }

    Injector<PathManager> getPathManagerInjector() {
        return pathManager;
    }

    @Override
    public Provider[] getValue() throws IllegalStateException, IllegalArgumentException {
        return providers == null ? null : providers.clone();
    }

    private static class Property {

        private final String key;
        private final String value;

        private Property(String key, String value) {
            this.key = key;
            this.value = value;
        }

        private String getKey() {
            return key;
        }

        private String getValue() {
            return value;
        }
    }

    private static class ProviderConfig {

        private final String module;
        private final boolean loadServices;
        private final String[] classNames;
        private final String path;
        private final String relativeTo;
        private final List<Property> propertyList;

        private ProviderConfig(String module, boolean loadServices, String[] classNames, String path, String relativeTo, List<Property> propertyList) {
            this.module = module;
            this.loadServices = loadServices;
            this.classNames = classNames;
            this.path = path;
            this.relativeTo = relativeTo;
            this.propertyList = propertyList;
        }

        private String getModule() {
            return module;
        }

        private boolean loadServices() {
            return loadServices;
        }

        private String[] getClassNames() {
            return classNames;
        }

        private String getPath() {
            return path;
        }

        private String getRelativeTo() {
            return relativeTo;
        }

        private List<Property> getPropertyList() {
            return propertyList;
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
        private boolean loadServices;
        private String[] classNames;
        private String path;
        private String relativeTo;
        private List<Property> propertyList;

        private ProviderConfigBuilder(ProviderLoaderServiceBuilder serviceBuilder) {
            this.serviceBuilder = serviceBuilder;
        }

        ProviderConfigBuilder setModule(String module) {
            this.module = module;

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

        ProviderConfigBuilder setPath(String path) {
            this.path = path;

            return this;
        }

        ProviderConfigBuilder setRelativeTo(String relativeTo) {
            this.relativeTo = relativeTo;

            return this;
        }

        PropertyListBuilder addPropertyList() {
            return new PropertyListBuilder(this);
        }

        private ProviderConfigBuilder setPropertyList(final List<Property> propertyList) {
            this.propertyList = propertyList;

            return this;
        }

        ProviderLoaderServiceBuilder build() {
            serviceBuilder.add(new ProviderConfig(module, loadServices, classNames, path, relativeTo, propertyList));

            return serviceBuilder;
        }
    }

    static class PropertyListBuilder {

        private final ProviderConfigBuilder configBuilder;

        private final List<Property> propertyList = new ArrayList<Property>();

        private PropertyListBuilder(ProviderConfigBuilder configBuilder) {
            this.configBuilder = configBuilder;
        }

        PropertyListBuilder add(String key, String value) {
            propertyList.add(new Property(key, value));

            return this;
        }

        ProviderConfigBuilder build() {
            return configBuilder.setPropertyList(Collections.unmodifiableList(propertyList));
        }

    }

}
