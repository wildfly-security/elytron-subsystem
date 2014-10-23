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

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.operations.validation.StringLengthValidator;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.as.controller.registry.Resource;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceName;

/**
 * A {@link ResourceDefinition} for a single domain.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class DomainDefinition extends SimpleResourceDefinition {

    static final SimpleAttributeDefinition DEFAULT_REALM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.DEFAULT_REALM, ModelType.STRING, false)
             .setAllowExpression(false)
             .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
             .setValidator(new StringLengthValidator(1, Integer.MAX_VALUE, false, false))
             .build();

    static final StringListAttributeDefinition REALMS =  new StringListAttributeDefinition.Builder(ElytronDescriptionConstants.REALMS)
             .setAllowExpression(true)
             .setAllowNull(false)
             .build();

    private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { DEFAULT_REALM, REALMS };

    private static final DomainAddHandler ADD = new DomainAddHandler();
    private static final DomainRemoveHandler REMOVE = new DomainRemoveHandler(ADD);
    private static final WiteAttributeHandler WRITE = new WiteAttributeHandler(ElytronDescriptionConstants.DOMAIN);

    DomainDefinition() {
        super(PathElement.pathElement(ElytronDescriptionConstants.DOMAIN),
                ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.DOMAIN),
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

    private static class DomainAddHandler extends AbstractAddStepHandler {

        private DomainAddHandler() {
            super(ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, Resource resource)
                throws OperationFailedException {
            super.performRuntime(context, operation, resource);


        }

        @Override
        protected void rollbackRuntime(OperationContext context, ModelNode operation, Resource resource) {
            super.rollbackRuntime(context, operation, resource);


        }

    }

    private static class DomainRemoveHandler extends ServiceRemoveStepHandler {

        public DomainRemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return super.serviceName(name);
        }


    }

    private static class WiteAttributeHandler extends RestartParentWriteAttributeHandler {

        public WiteAttributeHandler(String parentKeyName) {
            super(parentKeyName, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress parentAddress) {
            return null;
        }

    }

}
