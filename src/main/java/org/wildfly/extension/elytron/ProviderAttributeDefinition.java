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

import java.security.Provider;

import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;

/**
 * Class to contain the attribute definition for the runtime representation of a security provider.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ProviderAttributeDefinition {

    private static final SimpleAttributeDefinition NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.NAME, ModelType.STRING).build();

    private static final SimpleAttributeDefinition INFO = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.INFO, ModelType.STRING).build();

    private static final SimpleAttributeDefinition VERSION = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.VERSION, ModelType.DOUBLE).build();

    static final ObjectTypeAttributeDefinition LOADED_PROVIDER = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.LOADED_PROVIDER, NAME, INFO, VERSION)
        .setStorageRuntime()
        .setAllowNull(false)
        .build();

    private ProviderAttributeDefinition() {
    }

    /**
     * Populate the supplied response {@link ModelNode} with information about the supplied {@link Provider}
     *
     * @param response the response to populate.
     * @param provider the {@link Provider} to use when populating the response.
     */
    static void populateResponse(final ModelNode response, final Provider provider) {
        response.get(ElytronDescriptionConstants.NAME).set(provider.getName());
        response.get(ElytronDescriptionConstants.INFO).set(provider.getInfo());
        response.get(ElytronDescriptionConstants.VERSION).set(provider.getVersion());
    }
}
