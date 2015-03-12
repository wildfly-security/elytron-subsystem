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

import static org.wildfly.extension.elytron.SecurityRealmServiceUtil.realmServiceName;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.extension.elytron.junk.DummyRealmService;
import org.wildfly.security.auth.provider.SecurityRealm;

/**
 * A {@link ResourceDefinition} for a single realm.
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
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            ServiceName realmName = realmServiceName(operation);
            Service<SecurityRealm> realm = new DummyRealmService();

            serviceTarget.addService(realmName, realm)
                    .setInitialMode(Mode.LAZY)
                    .install();
        }

    }

    private static class RealmRemoveHandler extends ServiceRemoveStepHandler {

        public RealmRemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return realmServiceName(name);
        }

    }
}
