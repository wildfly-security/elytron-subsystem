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
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORE;
import static org.wildfly.extension.elytron.ElytronExtension.BASE_SERVICE_NAME;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.KeyStore;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceName;

/**
 * A utility class for creating a {@link ServiceName} for KeyStores and handling injection.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class KeyStoreServiceUtil {

    private KeyStoreServiceUtil() {
        // Prevent Instantiation.
    }

    /**
     * Construct the {@link ServiceName} for a KeyStore given it's simple name.
     *
     * @param name - the simple name of the KeyStore.
     * @return The fully qualified {@link ServiceName} of the KeyStore.
     */
    static ServiceName keyStoreServiceName(final String name) {
        return BASE_SERVICE_NAME.append(KEYSTORE, name);
    }

    /**
     * From a given operation extract the address of the operation, identify the simple name of the KeyStore being referenced and
     * convert it into a {@link ServiceName} for that KeyStore.
     *
     * @param operation - the operation to extract the KeyStore name from.
     * @return The fully qualified {@link ServiceName} of the KeyStore.
     */
    static ServiceName realmServiceName(final ModelNode operation) {
        String keyStoreName = null;
        PathAddress pa = PathAddress.pathAddress(operation.require(OP_ADDR));
        for (int i = pa.size() - 1; i > 0; i--) {
            PathElement pe = pa.getElement(i);
            if (KEYSTORE.equals(pe.getKey())) {
                keyStoreName = pe.getValue();
                break;
            }
        }

        if (keyStoreName == null) {
            throw ROOT_LOGGER.operationAddressMissingKey(KEYSTORE);
        }

        return keyStoreServiceName(keyStoreName);
    }

    /**
     * Using the supplied {@link Injector} add a dependency on the {@link KeyStore} identified by the supplied KeyStore name.
     *
     * @param sb - the {@link ServiceBuilder} to use for the injection.
     * @param injector - the {@link Injector} to inject into.
     * @param realmName - the name of the KeyStore to inject.
     * @return The {@link ServiceBuilder} passed in to allow method chaining.
     */
    static ServiceBuilder<?> keyStoreDependency(ServiceBuilder<?> sb, Injector<KeyStore> injector, String keyStoreName) {
        sb.addDependency(REQUIRED, keyStoreServiceName(keyStoreName), KeyStore.class, injector);

        return sb;
    }

}
