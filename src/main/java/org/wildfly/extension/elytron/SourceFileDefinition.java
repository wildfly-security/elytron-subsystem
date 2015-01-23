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

import java.security.KeyStore;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AbstractRemoveStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
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
 * A {@link ResourceDefinition} for the file to use to initialise the {@link KeyStore}.
 *
 * Note: This is the only source type currently supported, however a child resource is used as it
 * gives us scope in the future to add additional sources if needed.
 *
 * This resource is only responsible for model manipulation, the parent resource will use the
 * model for it's initialisation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SourceFileDefinition extends SimpleResourceDefinition {

    private static final OperationStepHandler ADD = new SourceFileAddHandler();
    private static final OperationStepHandler REMOVE = new SourceFileRemoveHandler();

    // Attributes
    static final SimpleAttributeDefinition RELATIVE_TO = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.RELATIVE_TO, ModelType.STRING, true)
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setValidator(new StringLengthValidator(1, Integer.MAX_VALUE, true, true))
        .build();

    static final SimpleAttributeDefinition PATH = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PATH, ModelType.STRING, false)
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setValidator(new StringLengthValidator(1, Integer.MAX_VALUE, true, true))
        .build();

    static final SimpleAttributeDefinition WATCH = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.WATCH, ModelType.BOOLEAN, true)
        .setDefaultValue(new ModelNode(true))
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition REQUIRED = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REQUIRED, ModelType.BOOLEAN, true)
        .setDefaultValue(new ModelNode(false))
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { RELATIVE_TO, PATH, WATCH, REQUIRED };
    private static final OperationStepHandler WRITE = new WriteAttributeHandler();

    // read-only


    SourceFileDefinition() {
        super(PathElement.pathElement(ElytronDescriptionConstants.SOURCE, ElytronDescriptionConstants.FILE),
                ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.KEYSTORE + "." + ElytronDescriptionConstants.FILE),
                ADD, REMOVE,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES, OperationEntry.Flag.RESTART_RESOURCE_SERVICES);
        // Need to double check the flags, really the parent needs to do something now.
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition current : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(current, null, WRITE);
        }
    }

    @Override
    public void registerOperations(ManagementResourceRegistration resourceRegistration) {

        // Save
        // Reload?

    }

    private static class SourceFileAddHandler extends AbstractAddStepHandler {

    }

    private static class SourceFileRemoveHandler extends AbstractRemoveStepHandler {

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
