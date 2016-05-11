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

import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;

import java.util.List;
import java.util.function.Function;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ListAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;

/**
 * A {@link ResourceDefinition} for components that are aggregations of the same type.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class AggregateComponentDefinition<T> extends SimpleResourceDefinition {

    private final ListAttributeDefinition aggregateReferences;
    private final OperationStepHandler attributeWriteHandler;
    private final RuntimeCapability<?> runtimeCapability;

    private AggregateComponentDefinition(Class<T> classType, String pathKey, OperationStepHandler addHandler, OperationStepHandler removeHandler,
            ListAttributeDefinition aggregateReferences, OperationStepHandler attributeWriteHandler, RuntimeCapability<?> runtimeCapability) {
        super(new Parameters(PathElement.pathElement(pathKey), ElytronExtension.getResourceDescriptionResolver(pathKey))
            .setAddHandler(addHandler)
            .setRemoveHandler(removeHandler)
            .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
            .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));

        this.aggregateReferences = aggregateReferences;
        this.attributeWriteHandler = attributeWriteHandler;
        this.runtimeCapability = runtimeCapability;
    }

    ListAttributeDefinition getReferencesAttribute() {
        return aggregateReferences;
    }

    /**
     * @see org.jboss.as.controller.SimpleResourceDefinition#registerAttributes(org.jboss.as.controller.registry.ManagementResourceRegistration)
     */
    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerReadWriteAttribute(aggregateReferences, null, attributeWriteHandler);
    }

    /**
     * @see org.jboss.as.controller.SimpleResourceDefinition#registerCapabilities(org.jboss.as.controller.registry.ManagementResourceRegistration)
     */
    @Override
    public void registerCapabilities(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerCapability(runtimeCapability);
    }

    static <T> AggregateComponentDefinition<T> create(Class<T> aggregationType, String componentName, String referencesName, RuntimeCapability<?> runtimeCapability, Function<T[], T> aggregator) {
        String capabilityName = runtimeCapability.getName();
        StringListAttributeDefinition aggregateReferences = new StringListAttributeDefinition.Builder(referencesName)
            .setMinSize(2)
            .setAllowNull(false)
            .setCapabilityReference(capabilityName, capabilityName, true)
            .build();

        AbstractAddStepHandler add = new AggregateComponentAddHandler<T>(aggregationType, aggregator, aggregateReferences, runtimeCapability);
        OperationStepHandler remove = new SingleCapabilityServiceRemoveHandler<T>(add, runtimeCapability, aggregationType);
        OperationStepHandler write = new WriteAttributeHandler<T>(aggregationType, runtimeCapability, componentName, aggregateReferences);

        return new AggregateComponentDefinition<T>(aggregationType, componentName, add, remove, aggregateReferences, write, runtimeCapability);
    }

    private static class AggregateComponentAddHandler<T> extends BaseAddHandler {

        private final Class<T> aggregationType;
        private final Function<T[], T> aggregator;
        private final StringListAttributeDefinition aggregateReferences;
        private final RuntimeCapability<?> runtimeCapability;

        private AggregateComponentAddHandler(Class<T> aggregationType, Function<T[], T> aggregator, StringListAttributeDefinition aggregateReferences, RuntimeCapability<?> runtimeCapability) {
            super(runtimeCapability, aggregateReferences);
            this.aggregationType = aggregationType;
            this.aggregator = aggregator;
            this.aggregateReferences = aggregateReferences;
            this.runtimeCapability = runtimeCapability;
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<?> instanceRuntimeCapability = runtimeCapability.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName componentName = instanceRuntimeCapability.getCapabilityServiceName(aggregationType);

            AggregateComponentService<T> aggregateComponentService = new AggregateComponentService<T>(aggregationType, aggregator);

            ServiceBuilder<T> serviceBuilder = serviceTarget.addService(componentName, aggregateComponentService);

            List<String> aggregates = aggregateReferences.unwrap(context, model);

            String baseCapabilityName = runtimeCapability.getName();
            for (String current : aggregates) {
                String runtimeCapabilityName = RuntimeCapability.buildDynamicCapabilityName(baseCapabilityName, current);
                ServiceName realmServiceName = context.getCapabilityServiceName(runtimeCapabilityName, aggregationType);

                serviceBuilder.addDependency(realmServiceName, aggregationType, aggregateComponentService.newInjector());
            }

            commonDependencies(serviceBuilder)
                .setInitialMode(Mode.LAZY)
                .install();

        }

    }

    private static class WriteAttributeHandler<T> extends RestartParentWriteAttributeHandler {

        private final Class<T> serviceType;
        private final RuntimeCapability<?> runtimeCapability;


        WriteAttributeHandler(Class<T> serviceType, RuntimeCapability<?> runtimeCapability, String pathKey, AttributeDefinition attribute) {
            super(pathKey, attribute);
            this.serviceType = serviceType;
            this.runtimeCapability = runtimeCapability;
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress pathAddress) {
            return runtimeCapability.fromBaseCapability(pathAddress.getLastElement().getValue()).getCapabilityServiceName(serviceType);
        }

    }

}
