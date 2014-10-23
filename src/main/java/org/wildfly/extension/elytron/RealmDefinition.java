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
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.as.controller.registry.Resource;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceName;

/**
 * A {@link ResourceDefinition} for a single domain.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class RealmDefinition extends SimpleResourceDefinition {

    private static final RealmAddHandler ADD = new RealmAddHandler();
    private static final RealmRemoveHandler REMOVE = new RealmRemoveHandler(ADD);

    RealmDefinition() {
        super(PathElement.pathElement(ElytronDescriptionConstants.REALM),
                ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.REALM),
                ADD, REMOVE,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES);
    }

    private static class RealmAddHandler extends AbstractAddStepHandler {

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

    private static class RealmRemoveHandler extends ServiceRemoveStepHandler {

        public RealmRemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return super.serviceName(name);
        }

    }
}
