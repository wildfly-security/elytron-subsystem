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

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ModelVersion;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.ServiceVerificationHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.operations.validation.StringLengthValidator;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceName;

/**
 * A {@link ResourceDefinition} for a single KeyStore.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class KeyStoreDefinition extends SimpleResourceDefinition {

    static final SimpleAttributeDefinition TYPE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.TYPE, ModelType.STRING, false)
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setValidator(new StringLengthValidator(1, Integer.MAX_VALUE, false, true))
        .build();

    static final SimpleAttributeDefinition PROVIDER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PROVIDER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setValidator(new StringLengthValidator(1, Integer.MAX_VALUE, true, true))
        .build();

    static final SimpleAttributeDefinition PASSWORD = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PASSWORD, ModelType.STRING, true)
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setValidator(new StringLengthValidator(1, Integer.MAX_VALUE, true, true))
        .setDeprecated(ModelVersion.create(1, 0)) // Deprecate immediately as to be supplied by the vault.
        .build();

    private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { TYPE, PROVIDER, PASSWORD };

    private static final KeyStoreAddHandler ADD = new KeyStoreAddHandler();
    private static final OperationStepHandler REMOVE = new KeyStoreRemoveHandler(ADD);
    private static final WriteAttributeHandler WRITE = new WriteAttributeHandler();

    // Attributes

    // Runtime Stuff
    //   certificate={alias}
    //   key={alias}

    KeyStoreDefinition() {
        super(PathElement.pathElement(ElytronDescriptionConstants.KEYSTORE),
                ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.KEYSTORE),
                ADD, REMOVE,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES);
    }


    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition current : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(current, null, WRITE);
        }
    }

    @Override
    public void registerChildren(ManagementResourceRegistration resourceRegistration) {
        /*
         * A file is the only currently supported source, however this leaves us able to add
         * alternatives if needed in the future.
         *
         * For now it is also assumed the source is the location to save to but we could
         * even conceivably support an alternative destination, e.g. we can read from X but write to Y.
         */
        resourceRegistration.registerSubModel(new SourceFileDefinition());
    }

    @Override
    public void registerOperations(ManagementResourceRegistration resourceRegistration) {
        super.registerOperations(resourceRegistration);
        // getAlias (Maybe just on child runtime resource)

        // Later

        // Create Key Pair / Certificate (Is this a special op or on a resource?)
        // Remove (Maybe on child runtime resource?)
        // Create CSR
        // Import certificate

        // Save an reload are directly related to the store being file based so the ops are on that resource.
    }


    private static class KeyStoreAddHandler extends AbstractAddStepHandler {

        private KeyStoreAddHandler() {
            super(ATTRIBUTES);
        }

    }

    private static class KeyStoreRemoveHandler extends ServiceRemoveStepHandler {

        private KeyStoreRemoveHandler(final AbstractAddStepHandler add) {
            super(add);
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler() {
            super(ElytronDescriptionConstants.KEYSTORE, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress arg0) {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        protected void recreateParentService(OperationContext arg0, PathAddress arg1, ModelNode arg2,
                ServiceVerificationHandler arg3) throws OperationFailedException {
            // TODO Auto-generated method stub

        }

    }
}
