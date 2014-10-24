/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.DOMAIN;
import static org.wildfly.extension.elytron.ElytronExtension.BASE_SERVICE_NAME;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceName;
import org.wildfly.security.auth.provider.SecurityDomain;

/**
 * A utility class for creating a {@link ServiceName} for domains and handling injection.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SecurityDomainServiceUtil {

    private SecurityDomainServiceUtil() {
        // Prevent Instantiation.
    }

    /**
     * Construct the {@link ServiceName} for a domain given it's simple name.
     *
     * @param name - the simple name of the domain.
     * @return The fully qualified {@link ServiceName} of the domain.
     */
    public static ServiceName domainServiceName(final String name) {
        return BASE_SERVICE_NAME.append(DOMAIN, name);
    }

    /**
     * From a given operation extract the address of the operation, identify the simple name of the domain being referenced and
     * convert it into a {@link ServiceName} for that domain.
     *
     * @param operation - the operation to extract the domain name from.
     * @return The fully qualified {@link ServiceName} of the domain.
     */
    public static ServiceName domainServiceName(final ModelNode operation) {
        String domainName = null;
        PathAddress pa = PathAddress.pathAddress(operation.require(OP_ADDR));
        for (int i = pa.size() - 1; i > 0; i--) {
            PathElement pe = pa.getElement(i);
            if (DOMAIN.equals(pe.getKey())) {
                domainName = pe.getValue();
                break;
            }
        }

        if (domainName == null) {
            throw ROOT_LOGGER.operationAddressMissingKey(DOMAIN);
        }

        return domainServiceName(domainName);
    }

    /**
     * Using the supplied {@link Injector} add a dependency on the {@link SecurityDomain} identified by the supplied domain name.
     *
     * @param sb - the {@link ServiceBuilder} to use for the injection.
     * @param injector - the {@link Injector} to inject into.
     * @param domainName - the name of the domain to inject.
     * @return The {@link ServiceBuilder} passed in to allow method chaining.
     */
    public static ServiceBuilder<?> dinaubDependency(ServiceBuilder<?> sb, Injector<SecurityDomain> injector, String domainName) {
        sb.addDependency(REQUIRED, domainServiceName(domainName), SecurityDomain.class, injector);

        return sb;
    }

}
