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

import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.wildfly.extension.elytron.ElytronExtension.BASE_SERVICE_NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALM;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceName;
import org.wildfly.extension.elytron.junk.DummySecurityRealm;

/**
 * A simple {@link Service} that produces a {@link DummySecurityRealm}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class SecurityRealmServiceUtil {

    // Keeping visibility reduced at the moment as it is the domain that we really expect external access to.

    private SecurityRealmServiceUtil() {
        // Prevent Instantiation.
    }

    /**
     * Construct the {@link ServiceName} for a realm given it's simple name.
     *
     * @param name - the simple name of the realm.
     * @return The fully qualified {@link ServiceName} of the realm.
     */
    static ServiceName realmServiceName(final String name) {
        return BASE_SERVICE_NAME.append(REALM, name);
    }

    /**
     * From a given operation extract the addresss of the operation, identify the simple name of the realm being referenced and
     * convert it into a {@link ServiceName} for that realm.
     *
     * @param operation - the operation to extract the realm name from.
     * @return The fully qualified {@link ServiceName} of the realm.
     */
    static ServiceName realmServiceName(final ModelNode operation) {
        String realmName = null;
        PathAddress pa = PathAddress.pathAddress(operation.require(OP_ADDR));
        for (int i = pa.size() - 1; i > 0; i--) {
            PathElement pe = pa.getElement(i);
            if (REALM.equals(pe.getKey())) {
                realmName = pe.getValue();
                break;
            }
        }

        if (realmName == null) {
            throw ROOT_LOGGER.operationAddressMissingKey(REALM);
        }

        return realmServiceName(realmName);
    }

}
