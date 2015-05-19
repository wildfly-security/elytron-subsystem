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

import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceName;
import org.wildfly.security.auth.spi.SecurityRealm;

/**
 * A {@link ResourceDefinition} for a {@link SecurityRealm} backed by properties files.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PropertiesRealmDefinition extends SimpleResourceDefinition {

    static final ServiceUtil<SecurityRealm> REALM_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_REALM_RUNTIME_CAPABILITY, ElytronDescriptionConstants.PROPERTIES_REALM, SecurityRealm.class);

    static final ObjectTypeAttributeDefinition USERS_PROPERTIES = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.USERS_PROPERTIES, FileAttributeDefinitions.PATH, FileAttributeDefinitions.RELATIVE_TO)
        .setAllowNull(false)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final ObjectTypeAttributeDefinition GROUPS_PROPERTIES = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.GROUPS_PROPERTIES, FileAttributeDefinitions.PATH, FileAttributeDefinitions.RELATIVE_TO)
        .setAllowNull(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition PLAIN_TEXT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PLAIN_TEXT, ModelType.BOOLEAN, true)
        .setDefaultValue(new ModelNode(false))
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    private static AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { USERS_PROPERTIES, GROUPS_PROPERTIES, PLAIN_TEXT };

    private static final AbstractAddStepHandler ADD = new RealmAddHandler();
    private static final OperationStepHandler REMOVE = new RealmRemoveHandler(ADD);

    PropertiesRealmDefinition() {
        super(PathElement.pathElement(ElytronDescriptionConstants.PROPERTIES_REALM),
                ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.PROPERTIES_REALM),
                ADD, REMOVE,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES);
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        OperationStepHandler write = new WriteAttributeHandler();
        for (AttributeDefinition current : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(current, null, write);
        }
    }

    private static class RealmAddHandler extends AbstractAddStepHandler {

        private RealmAddHandler() {
            super(SECURITY_REALM_RUNTIME_CAPABILITY, ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            /*ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<Void> runtimeCapability = RuntimeCapability.fromBaseCapability(SECURITY_REALM_RUNTIME_CAPABILITY, context.getCurrentAddressValue());
            ServiceName realmName = runtimeCapability.getCapabilityServiceName(SecurityRealm.class);

            ModelNode configurationNode = CONFIGURATION.resolveModelAttribute(context, model);
            final String configuration = configurationNode.isDefined() ? configurationNode.asString() : context.getCurrentAddressValue();


            JaasRealmService jaasRealmService = new JaasRealmService(configuration);

            ServiceBuilder<SecurityRealm> serviceBuilder = serviceTarget.addService(realmName, jaasRealmService);
            commonDependencies(serviceBuilder)
                .setInitialMode(Mode.ACTIVE)
                .install();*/
        }

    }

    private static class RealmRemoveHandler extends ServiceRemoveStepHandler {

        public RealmRemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation, SECURITY_REALM_RUNTIME_CAPABILITY);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return REALM_SERVICE_UTIL.serviceName(name);
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler() {
            super(ElytronDescriptionConstants.PROPERTIES_REALM, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress arg0) {
            return null;
        }
    }


}
