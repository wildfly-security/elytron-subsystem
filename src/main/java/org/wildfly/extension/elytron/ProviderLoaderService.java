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

import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.ServiceLoader;

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
public class ProviderLoaderService implements Service<Provider[]> {

    private final String module;
    private final String slot;
    private final String[] classNames;
    private final boolean register;

    private volatile Provider[] providers;

    private ProviderLoaderService(final String module, final String slot, final String[] classNames, final boolean register) {
        this.module = module;
        this.slot = slot;
        this.classNames = classNames == null ? null : classNames.clone();
        this.register = register;
    }

    static Service<Provider[]> newInstance(final String module, final String slot, final String[] classNames, final boolean register) {
        return new ProviderLoaderService(module, slot, classNames, register);
    }

    @Override
    public void start(StartContext context) throws StartException {

        try {
            Provider[] providers = classNames == null ? loadProviders() : loadProviders(classNames);
            if (register) {
                registerProviders(providers);
            }
            this.providers = providers;
        } catch (ModuleLoadException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw ROOT_LOGGER.unableToStartService(e);
        }
    }

    private Provider[] loadProviders() throws ModuleLoadException {
        ClassLoader classLoader = resolveClassLoader();

        ServiceLoader<Provider> loader = ServiceLoader.load(Provider.class, classLoader);
        ArrayList<Provider> providers = new ArrayList<Provider>();
        loader.iterator().forEachRemaining((Provider p) -> providers.add(p));

        return providers.toArray(new Provider[providers.size()]);
    }

    private Provider[] loadProviders(String[] classNames) throws ModuleLoadException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        ClassLoader classLoader = resolveClassLoader();

        Provider[] providers = new Provider[classNames.length];
        for (int i = 0; i < classNames.length; i++) {
            Class<Provider> currentClass = (Class<Provider>) classLoader.loadClass(classNames[i]);
            providers[i] = currentClass.newInstance();
        }

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

    private ClassLoader resolveClassLoader() throws ModuleLoadException {
        Module current = Module.getCallerModule();
        if (module != null) {
            ModuleIdentifier mi = ModuleIdentifier.create(module, slot);
            current = current.getModule(mi);
        }

        return current.getClassLoader();
    }

    @Override
    public void stop(StopContext context) {
        if (register) {
            for (int i = providers.length - 1; i < 0; i--) {
                Security.removeProvider(providers[i].getName());
            }
        }

        providers = null;
    }

    @Override
    public Provider[] getValue() throws IllegalStateException, IllegalArgumentException {
        return providers == null ? null : providers.clone();
    }
}
