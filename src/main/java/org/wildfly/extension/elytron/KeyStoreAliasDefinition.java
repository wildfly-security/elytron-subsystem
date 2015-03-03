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
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORE;
import static org.wildfly.extension.elytron.KeyStoreDefinition.ISO_8601_FORMAT;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.KeyStoreException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.wildfly.extension.elytron.KeyStoreDefinition.ReadAttributeHandler;

/**
 * A {@link ResourceDefinition} for an alias stored within a {@link KeyStore}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class KeyStoreAliasDefinition extends SimpleResourceDefinition {

    static final SimpleAttributeDefinition CREATION_DATE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CREATION_DATE, ModelType.STRING)
        .setStorageRuntime()
        .build();

    KeyStoreAliasDefinition() {
        super(PathElement.pathElement(ElytronDescriptionConstants.ALIAS), ElytronExtension
                .getResourceDescriptionResolver(ElytronDescriptionConstants.KEYSTORE, ElytronDescriptionConstants.ALIAS));
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerReadOnlyAttribute(CREATION_DATE, new ReadAttributeHandler() {

            @Override
            protected void populateResult(ModelNode result, ModelNode operation, KeyStoreService keyStoreService) throws OperationFailedException {
                SimpleDateFormat sdf = new SimpleDateFormat(ISO_8601_FORMAT);

                String alias = alias(operation);

                Date creationDate;
                try {
                    creationDate = keyStoreService.getValue().getCreationDate(alias);
                } catch (KeyStoreException | IllegalStateException | IllegalArgumentException e) {
                    throw new OperationFailedException(e);
                }

                result.set(sdf.format(creationDate));
            }
        });
    }

    private static String alias(ModelNode operation) {
        String aliasName = null;
        PathAddress pa = PathAddress.pathAddress(operation.require(OP_ADDR));
        for (int i = pa.size() - 1; i > 0; i--) {
            PathElement pe = pa.getElement(i);
            if (ElytronDescriptionConstants.ALIAS.equals(pe.getKey())) {
                aliasName = pe.getValue();
                break;
            }
        }

        if (aliasName == null) {
            throw ROOT_LOGGER.operationAddressMissingKey(ElytronDescriptionConstants.ALIAS);
        }

        return aliasName;
    }

}
