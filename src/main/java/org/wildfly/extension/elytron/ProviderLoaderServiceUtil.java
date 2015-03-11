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

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.msc.service.ServiceBuilder.DependencyType.REQUIRED;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PROVIDER_LOADER;
import static org.wildfly.extension.elytron.ElytronExtension.BASE_SERVICE_NAME;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.Provider;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceName;

/**
 * A utility class for creating a {@link ServiceName} for ProviderLoaders and handling injection.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ProviderLoaderServiceUtil {

    private ProviderLoaderServiceUtil() {
        // Prevent Instantiation.
    }

    /**
     * Construct the {@link ServiceName} for a provider loader given it's simple name.
     *
     * @param name - the simple name of the provider loader.
     * @return The fully qualified {@link ServiceName} of the provider loader.
     */
    static ServiceName providerLoaderServiceName(final String name) {
        return BASE_SERVICE_NAME.append(PROVIDER_LOADER, name);
    }

    /**
     * From a given operation extract the address of the operation, identify the simple name of the provider loader being referenced and
     * convert it into a {@link ServiceName} for that provider loader.
     *
     * @param operation - the operation to extract the provider loader name from.
     * @return The fully qualified {@link ServiceName} of the provider loader.
     */
    static ServiceName providerLoaderServiceName(final ModelNode operation) {
        String keyStoreName = null;
        PathAddress pa = PathAddress.pathAddress(operation.require(OP_ADDR));
        for (int i = pa.size() - 1; i > 0; i--) {
            PathElement pe = pa.getElement(i);
            if (PROVIDER_LOADER.equals(pe.getKey())) {
                keyStoreName = pe.getValue();
                break;
            }
        }

        if (keyStoreName == null) {
            throw ROOT_LOGGER.operationAddressMissingKey(PROVIDER_LOADER);
        }

        return providerLoaderServiceName(keyStoreName);
    }

    /**
     * Using the supplied {@link Injector} add a dependency on the provider loader identified by the supplied KeyStore name.
     *
     * @param sb - the {@link ServiceBuilder} to use for the injection.
     * @param injector - the {@link Injector} to inject into.
     * @param providerLoaderName - the name of the provider loader to inject.
     * @return The {@link ServiceBuilder} passed in to allow method chaining.
     */
    static ServiceBuilder<?> providerLoaderDependency(ServiceBuilder<?> sb, Injector<Provider[]> injector, String providerLoaderName) {
        sb.addDependency(REQUIRED, providerLoaderServiceName(providerLoaderName), Provider[].class, injector);

        return sb;
    }

}
