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

import static org.wildfly.extension.elytron.Capabilities.ROLE_DECODER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
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
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.security.auth.util.RealmMapper;
import org.wildfly.security.authz.RoleDecoder;

/**
 * Container class for the {@link RoleDecoder} definitions.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class RoleDecoderDefinitions {

    static final SimpleAttributeDefinition ATTRIBUTE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ATTRIBUTE, ModelType.STRING, false)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static ResourceDefinition getEmptyRoleDecoderDefinition() {
        return EmptyResourceDefinition.create(RoleDecoder.class, ElytronDescriptionConstants.EMPTY_ROLE_DECODER, ROLE_DECODER_RUNTIME_CAPABILITY, () -> RoleDecoder.EMPTY);
    }

    static ResourceDefinition getSimpleRoleDecoderDefinition() {
        return new SimpleRoleDecoderDefinition();
    }

    private static class SimpleRoleDecoderDefinition extends SimpleResourceDefinition {

        private static final AbstractAddStepHandler ADD = new SimpleRoleDecoderAddHandler();
        private static final OperationStepHandler REMOVE = new RoleDecoderRemoveHandler(ADD);

        SimpleRoleDecoderDefinition() {
            super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.SIMPLE_ROLE_DECODER), ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.SIMPLE_ROLE_DECODER))
                .setAddHandler(ADD)
                .setRemoveHandler(REMOVE)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
        }

        @Override
        public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
            resourceRegistration.registerReadWriteAttribute(ATTRIBUTE, null, new WriteAttributeHandler(ElytronDescriptionConstants.SIMPLE_ROLE_DECODER, ATTRIBUTE));
        }

    }

    private static class SimpleRoleDecoderAddHandler extends AbstractAddStepHandler {

        private SimpleRoleDecoderAddHandler() {
            super(ROLE_DECODER_RUNTIME_CAPABILITY, ATTRIBUTE);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<Void> runtimeCapability = RuntimeCapability.fromBaseCapability(ROLE_DECODER_RUNTIME_CAPABILITY, context.getCurrentAddressValue());
            ServiceName roleDecoderName = runtimeCapability.getCapabilityServiceName(RoleDecoder.class);

            final String attribute = ATTRIBUTE.resolveModelAttribute(context, model).asString();
            TrivialService<RoleDecoder> roleDecoderService = new TrivialService<RoleDecoder>(() -> RoleDecoder.simple(attribute));

            ServiceBuilder<RoleDecoder> roleDecoderBuilderBuilder = serviceTarget.addService(roleDecoderName, roleDecoderService);

            commonDependencies(roleDecoderBuilderBuilder)
                .setInitialMode(Mode.LAZY)
                .install();
        }

    }

    private static class RoleDecoderRemoveHandler extends ServiceRemoveStepHandler {

        public RoleDecoderRemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation, ROLE_DECODER_RUNTIME_CAPABILITY);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return RuntimeCapability.fromBaseCapability(ROLE_DECODER_RUNTIME_CAPABILITY, name).getCapabilityServiceName(RealmMapper.class);
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler(String parentName, AttributeDefinition ... attributes) {
            super(parentName, attributes);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress arg0) {
            return null;
        }
    }
}
