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

import static org.wildfly.extension.elytron.Capabilities.PRINCIPAL_DECODER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PRINCIPAL_DECODERS;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
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
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.x500.X500AttributePrincipalDecoder;


/**
 * Holder for {@link ResourceDefinition} instances for services that return {@link PrincipalDecoder}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class PrincipalDecoderDefinitions {

    static final SimpleAttributeDefinition OID = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.OID, ModelType.STRING, false)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition JOINER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.JOINER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setDefaultValue(new ModelNode("."))
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition MAXIMUM_SEGMENTS = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.MAXIMUM_SEGMENTS, ModelType.INT, true)
        .setAllowExpression(true)
        .setDefaultValue(new ModelNode(Integer.MAX_VALUE))
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    private static final AggregateComponentDefinition<PrincipalDecoder> AGGREGATE_PRINCIPAL_DECODER = AggregateComponentDefinition.create(PrincipalDecoder.class,
            ElytronDescriptionConstants.AGGREGATE_PRINCIPAL_DECODER, PRINCIPAL_DECODERS, PRINCIPAL_DECODER_RUNTIME_CAPABILITY, PrincipalDecoder::aggregate);

    static AggregateComponentDefinition<PrincipalDecoder> getAggregatePrincipalDecoderDefinition() {
        return AGGREGATE_PRINCIPAL_DECODER;
    }

    static ResourceDefinition getX500AttributePrincipalDecoder() {
        AttributeDefinition[] attributes = new AttributeDefinition[] { OID, JOINER, MAXIMUM_SEGMENTS };
        AbstractAddStepHandler add = new PrincipalDecoderAddHander(attributes) {

            @Override
            protected ValueSupplier<PrincipalDecoder> getValueSupplier(OperationContext context, ModelNode model) throws OperationFailedException {
                final String oid = OID.resolveModelAttribute(context, model).asString();
                final String joiner = JOINER.resolveModelAttribute(context, model).asString();
                final int maximumSegments = MAXIMUM_SEGMENTS.resolveModelAttribute(context, model).asInt();
                return () -> new X500AttributePrincipalDecoder(oid, joiner, maximumSegments);
            }

        };

        return new PrincipalDecoderResourceDefinition(ElytronDescriptionConstants.X500_ATTRIBUTE_PRINCIPAL_DECODER, add, attributes);
    }

    private static class PrincipalDecoderResourceDefinition extends SimpleResourceDefinition {

        private final String pathKey;
        private final AttributeDefinition[] attributes;

        PrincipalDecoderResourceDefinition(String pathKey, AbstractAddStepHandler add, AttributeDefinition ... attributes) {
            super(new Parameters(PathElement.pathElement(pathKey),
                    ElytronExtension.getResourceDescriptionResolver(pathKey))
                .setAddHandler(add)
                .setRemoveHandler(new SingleCapabilityServiceRemoveHandler<PrincipalDecoder>(add, PRINCIPAL_DECODER_RUNTIME_CAPABILITY, PrincipalDecoder.class))
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
            this.pathKey = pathKey;
            this.attributes = attributes;
        }

        @Override
        public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
             if (attributes != null && attributes.length > 0) {
                 WriteAttributeHandler write = new WriteAttributeHandler(pathKey, attributes);
                 for (AttributeDefinition current : attributes) {
                     resourceRegistration.registerReadWriteAttribute(current, null, write);
                 }
             }
        }

        @Override
        public void registerCapabilities(ManagementResourceRegistration resourceRegistration) {
            resourceRegistration.registerCapability(PRINCIPAL_DECODER_RUNTIME_CAPABILITY);
        }

    }

    private static class PrincipalDecoderAddHander extends AbstractAddStepHandler {


        private PrincipalDecoderAddHander(AttributeDefinition ... attributes) {
            super(PRINCIPAL_DECODER_RUNTIME_CAPABILITY, attributes);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            RuntimeCapability<Void> runtimeCapability = PRINCIPAL_DECODER_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName roleMapperName = runtimeCapability.getCapabilityServiceName(PrincipalDecoder.class);

            commonDependencies(installService(context, roleMapperName, model))
                .setInitialMode(Mode.LAZY)
                .install();
        }

        protected ServiceBuilder<PrincipalDecoder> installService(OperationContext context, ServiceName principalDecoderName, ModelNode model) throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            TrivialService<PrincipalDecoder> roleMapperService = new TrivialService<PrincipalDecoder>(getValueSupplier(context, model));

            return serviceTarget.addService(principalDecoderName, roleMapperService);
        }

        protected ValueSupplier<PrincipalDecoder> getValueSupplier(OperationContext context, ModelNode model) throws OperationFailedException {
            return () -> null;
        };

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler(String parentName, AttributeDefinition ... attributes) {
            super(parentName, attributes);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress pathAddress) {
            return PRINCIPAL_DECODER_RUNTIME_CAPABILITY.fromBaseCapability(pathAddress.getLastElement().getValue()).getCapabilityServiceName(PrincipalDecoder.class);
        }
    }

}
