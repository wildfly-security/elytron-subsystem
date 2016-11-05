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

import static org.wildfly.extension.elytron.Capabilities.PROVIDERS_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.CLASS_NAMES;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.MODULE;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.ElytronExtension.getRequiredService;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.pathName;
import static org.wildfly.extension.elytron.ProviderAttributeDefinition.INDEXED_PROVIDERS;
import static org.wildfly.extension.elytron.ProviderAttributeDefinition.LOADED_PROVIDERS;
import static org.wildfly.extension.elytron.ProviderAttributeDefinition.PROVIDERS;
import static org.wildfly.extension.elytron.ProviderAttributeDefinition.populateProviders;

import java.security.Provider;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AbstractRuntimeOnlyHandler;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleOperationDefinition;
import org.jboss.as.controller.SimpleOperationDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.controller.descriptions.StandardResourceDescriptionResolver;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.as.controller.services.path.PathManagerService;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceController.State;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.extension.elytron.ProviderLoaderService.PropertyListBuilder;
import org.wildfly.extension.elytron.ProviderLoaderService.ProviderConfigBuilder;
import org.wildfly.extension.elytron.ProviderLoaderService.ProviderLoaderServiceBuilder;

/**
 * A {@link ResourceDefinition} for a loader of {@link Provider}s.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ProviderLoaderDefinition extends SimpleResourceDefinition {

    static final ServiceUtil<Provider[]> PROVIDER_LOADER_SERVICE_UTIL = ServiceUtil.newInstance(PROVIDERS_RUNTIME_CAPABILITY, ElytronDescriptionConstants.PROVIDER_LOADER, Provider[].class);

    static final SimpleAttributeDefinition REGISTER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REGISTER, ModelType.BOOLEAN, true)
        .setDefaultValue(new ModelNode(false))
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    private static final AbstractAddStepHandler ADD = new ProviderAddHandler();
    private static final OperationStepHandler REMOVE = new TrivialCapabilityServiceRemoveHandler(ADD, PROVIDERS_RUNTIME_CAPABILITY);
    private static final OperationStepHandler WRITE = new WriteAttributeHandler();

    private static final StandardResourceDescriptionResolver RESOLVER = ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.PROVIDER_LOADER);

    private static final SimpleOperationDefinition ADD_DEFINITION = new SimpleOperationDefinitionBuilder(ModelDescriptionConstants.ADD, RESOLVER)
        .setParameters(REGISTER, PROVIDERS)
        .build();

    ProviderLoaderDefinition() {
        super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.PROVIDER_LOADER), RESOLVER)
                .setRemoveHandler(REMOVE)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setCapabilities(PROVIDERS_RUNTIME_CAPABILITY));
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerReadWriteAttribute(REGISTER, null, WRITE);

        resourceRegistration.registerReadOnlyAttribute(INDEXED_PROVIDERS, new ProvidersAttributeHandler());
        resourceRegistration.registerReadOnlyAttribute(LOADED_PROVIDERS, new LoadedProvidersAttributeHandler());
    }

    @Override
    public void registerOperations(ManagementResourceRegistration resourceRegistration) {
        super.registerOperations(resourceRegistration);
        // We needed a custom add operation so we could specify the parameters.
        resourceRegistration.registerOperationHandler(ADD_DEFINITION, ADD);
    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler() {
            super(ElytronDescriptionConstants.PROVIDER_LOADER, REGISTER);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress pathAddress) {
            return PROVIDERS_RUNTIME_CAPABILITY.fromBaseCapability(pathAddress.getLastElement().getValue()).getCapabilityServiceName(Provider[].class);
        }

    }

    private static class ProviderAddHandler extends BaseAddHandler {

        ProviderAddHandler() {
            super(PROVIDERS_RUNTIME_CAPABILITY, REGISTER, PROVIDERS);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, Resource resource) throws OperationFailedException {
            ModelNode model = resource.getModel();

            ProviderLoaderServiceBuilder builder = ProviderLoaderService.builder();
            builder.setRegister(ProviderLoaderDefinition.REGISTER.resolveModelAttribute(context, model).asBoolean());

            Set<String> relativeToSet = new HashSet<String>();

            if (model.hasDefined(ElytronDescriptionConstants.PROVIDERS)) {
                List<ModelNode> nodes = model.require(ElytronDescriptionConstants.PROVIDERS).asList();
                for (ModelNode current : nodes) {
                    ProviderConfigBuilder providerBuilder = builder.addProviderConfig()
                    .setModule(asStringIfDefined(context, MODULE, current))
                    .setLoadServices(ProviderAttributeDefinition.LOAD_SERVICES.resolveModelAttribute(context, current).asBoolean())
                    .setClassNames(asStringArrayIfDefined(context, CLASS_NAMES, current))
                    .setPath(asStringIfDefined(context, FileAttributeDefinitions.PATH, current));

                    String relativeTo = asStringIfDefined(context, FileAttributeDefinitions.RELATIVE_TO, current);
                    if (relativeTo != null) {
                        providerBuilder.setRelativeTo(relativeTo);
                        relativeToSet.add(relativeTo);
                    }

                    if (current.hasDefined(ElytronDescriptionConstants.PROPERTY_LIST)) {
                        PropertyListBuilder propertyBuilder = providerBuilder.addPropertyList();
                        for (ModelNode currentProp : current.require(ElytronDescriptionConstants.PROPERTY_LIST).asList()) {
                            propertyBuilder.add(ProviderAttributeDefinition.PROPERTY_NAME.resolveModelAttribute(context, currentProp).asString(),
                                    ProviderAttributeDefinition.VALUE.resolveModelAttribute(context, currentProp).asString());
                        }
                        providerBuilder = propertyBuilder.build();
                    }

                    providerBuilder.build();
                }
            }

            ProviderLoaderService providerLoaderService = builder.build();
            RuntimeCapability<Void> runtimeCapability = PROVIDERS_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName serviceName = runtimeCapability.getCapabilityServiceName(Provider[].class);
            ServiceTarget serviceTarget = context.getServiceTarget();
            ServiceBuilder<Provider[]> serviceBuilder = serviceTarget.addService(serviceName, providerLoaderService)
                    .setInitialMode(Mode.ACTIVE);

            if (relativeToSet.isEmpty() == false) {
                serviceBuilder.addDependency(PathManagerService.SERVICE_NAME, PathManager.class, providerLoaderService.getPathManagerInjector());
                for (String relativeTo : relativeToSet) {
                    serviceBuilder.addDependency(pathName(relativeTo));
                }
            }

            commonDependencies(serviceBuilder);
            serviceBuilder.install();
        }
    }

    private static String[] asStringArrayIfDefined(OperationContext context, StringListAttributeDefinition attributeDefinition, ModelNode model) throws OperationFailedException {
        ModelNode resolved = attributeDefinition.resolveModelAttribute(context, model);
        if (resolved.isDefined()) {
            List<ModelNode> values = resolved.asList();
            String[] response = new String[values.size()];
            for (int i = 0; i < response.length; i++) {
                response[i] = values.get(i).asString();
            }
            return response;
        }
        return null;
    }

    private static class ProvidersAttributeHandler implements OperationStepHandler {

        @Override
        public void execute(OperationContext context, ModelNode operation) throws OperationFailedException {
            ModelNode model = context.readResource(PathAddress.EMPTY_ADDRESS).getModel();
            ModelNode result = context.getResult();

            if (model.hasDefined(ElytronDescriptionConstants.PROVIDERS)) {
                int index = 0;
                model.require(ElytronDescriptionConstants.PROVIDERS).asList().iterator().forEachRemaining((ModelNode m) -> result.add(m));
                for (ModelNode currentProvider : result.asList()) {
                    currentProvider.get(ElytronDescriptionConstants.INDEX).set(index++);
                }
            }
        }
    }

    private static class LoadedProvidersAttributeHandler extends AbstractRuntimeOnlyHandler {

        @Override
        protected void executeRuntimeStep(OperationContext context, ModelNode operation) throws OperationFailedException {
            ServiceName providerLoaderName = PROVIDER_LOADER_SERVICE_UTIL.serviceName(operation);
            ServiceController<Provider[]> serviceContainer = getRequiredService(context.getServiceRegistry(false), providerLoaderName, Provider[].class);
            if (serviceContainer.getState() != State.UP) {
                return;
            }

            populateProviders(context.getResult(), serviceContainer.getValue());
        }

    }

}
