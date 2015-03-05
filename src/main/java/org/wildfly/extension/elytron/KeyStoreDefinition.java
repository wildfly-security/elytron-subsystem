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

import static org.wildfly.extension.elytron.ElytronExtension.ELYTRON_1_0_0;
import static org.wildfly.extension.elytron.ElytronExtension.registerRuntimeResource;
import static org.wildfly.extension.elytron.KeyStoreServiceUtil.keyStoreServiceName;
import static org.wildfly.extension.elytron.ProviderAttributeDefinition.LOADED_PROVIDER;
import static org.wildfly.extension.elytron.ProviderAttributeDefinition.populateResponse;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AbstractRuntimeOnlyHandler;
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
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.controller.operations.validation.StringLengthValidator;
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

/**
 * A {@link ResourceDefinition} for a single KeyStore.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class KeyStoreDefinition extends SimpleResourceDefinition {

    static final String ISO_8601_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";

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
        .setDeprecated(ELYTRON_1_0_0) // Deprecate immediately as to be supplied by the vault.
        .build();

    static final SimpleAttributeDefinition PATH = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PATH, ModelType.STRING, true)
        .setAllowExpression(true)
        .setAttributeGroup(ElytronDescriptionConstants.FILE)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setValidator(new StringLengthValidator(1, Integer.MAX_VALUE, true, true))
        .build();

    static final SimpleAttributeDefinition RELATIVE_TO = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.RELATIVE_TO, ModelType.STRING, true)
        .setAllowExpression(true)
        .setAttributeGroup(ElytronDescriptionConstants.FILE)
        .setRequires(ElytronDescriptionConstants.PATH)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setValidator(new StringLengthValidator(1, Integer.MAX_VALUE, true, true))
        .build();

    static final SimpleAttributeDefinition WATCH = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.WATCH, ModelType.BOOLEAN, true)
        .setDefaultValue(new ModelNode(true))
        .setAllowExpression(true)
        .setAttributeGroup(ElytronDescriptionConstants.FILE)
        .setRequires(ElytronDescriptionConstants.PATH)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition REQUIRED = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REQUIRED, ModelType.BOOLEAN, true)
        .setDefaultValue(new ModelNode(false))
        .setAllowExpression(true)
        .setAttributeGroup(ElytronDescriptionConstants.FILE)
        .setRequires(ElytronDescriptionConstants.PATH)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    // Runtime Attributes

    static final SimpleAttributeDefinition SIZE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SIZE, ModelType.INT)
        .setStorageRuntime()
        .build();

    static final SimpleAttributeDefinition LOADED = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.LOADED, ModelType.STRING)
        .setStorageRuntime()
        .build();

    private static final AttributeDefinition[] CONFIG_ATTRIBUTES = new AttributeDefinition[] { TYPE, PROVIDER, PASSWORD, PATH, RELATIVE_TO, WATCH, REQUIRED };

    private static final KeyStoreAddHandler ADD = new KeyStoreAddHandler();
    private static final OperationStepHandler REMOVE = new KeyStoreRemoveHandler(ADD);
    private static final WriteAttributeHandler WRITE = new WriteAttributeHandler();

    KeyStoreDefinition() {
        super(PathElement.pathElement(ElytronDescriptionConstants.KEYSTORE),
                ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.KEYSTORE),
                ADD, REMOVE,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES);
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition current : CONFIG_ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(current, null, WRITE);
        }
        resourceRegistration.registerReadOnlyAttribute(SIZE, new KeyStoreRuntimeOnlyHandler(false) {

            @Override
            protected void performRuntime(ModelNode result, ModelNode operation, KeyStoreService keyStoreService) throws OperationFailedException {
                try {
                    result.set(keyStoreService.getValue().size());
                } catch (KeyStoreException e) {
                    throw ROOT_LOGGER.unableToAccessKeyStore(e);
                }
            }
        });

        resourceRegistration.registerReadOnlyAttribute(LOADED, new KeyStoreRuntimeOnlyHandler(false) {

            @Override
            protected void performRuntime(ModelNode result, ModelNode operation, KeyStoreService keyStoreService) throws OperationFailedException {
                SimpleDateFormat sdf = new SimpleDateFormat(ISO_8601_FORMAT);
                result.set(sdf.format(new Date(keyStoreService.timeLoaded())));
            }
        });

        resourceRegistration.registerReadOnlyAttribute(LOADED_PROVIDER, new KeyStoreRuntimeOnlyHandler(false) {

            @Override
            protected void performRuntime(ModelNode result, ModelNode operation, KeyStoreService keyStoreService)
                    throws OperationFailedException {
                populateResponse(result, keyStoreService.getValue().getProvider());
            }
        });
    }

    @Override
    public void registerOperations(ManagementResourceRegistration resourceRegistration) {
        super.registerOperations(resourceRegistration);
        // Later

        // Create Key Pair / Certificate (Is this a special op or on a resource?)
        // Remove (Maybe on child runtime resource?)
        // Create CSR
        // Import certificate

        // reload / save - can probably support reload in all cases, save should be no-op where no file.
    }

    @Override
    public void registerChildren(ManagementResourceRegistration resourceRegistration) {
        registerRuntimeResource(resourceRegistration, new KeyStoreAliasDefinition());
    }

    private static class KeyStoreAddHandler extends AbstractAddStepHandler {

        private KeyStoreAddHandler() {
            super(CONFIG_ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, Resource resource) throws OperationFailedException {
            ModelNode model = resource.getModel();
            String provider = asStringIfDefined(context, PROVIDER, model);
            String type = TYPE.resolveModelAttribute(context, model).asString();
            String password = asStringIfDefined(context, PASSWORD, model);
            String path = asStringIfDefined(context, PATH, model);
            String relativeTo = null;
            boolean required;
            boolean watch;

            final KeyStoreService keyStoreService;
            if (path != null) {
                relativeTo = asStringIfDefined(context, RELATIVE_TO, model);
                required = REQUIRED.resolveModelAttribute(context, model).asBoolean();
                watch = WATCH.resolveModelAttribute(context, model).asBoolean();

                keyStoreService = KeyStoreService.createFileBasedKeyStoreService(provider, type, password.toCharArray(), relativeTo, path, required, watch);
            } else {
                keyStoreService = KeyStoreService.createFileLessKeyStoreService(provider, type, password.toCharArray());
            }

            ServiceTarget serviceTarget = context.getServiceTarget();
            ServiceName serviceName = keyStoreServiceName(operation);
            ServiceBuilder<KeyStore> serviceBuilder = serviceTarget.addService(serviceName, keyStoreService)
                    .setInitialMode(Mode.ACTIVE);

            if (relativeTo != null) {
                serviceBuilder.addDependency(PathManagerService.SERVICE_NAME, PathManager.class, keyStoreService.getPathManagerInjector());
                serviceBuilder.addDependency(pathName(relativeTo));
            }
            ServiceController<KeyStore> serviceController = serviceBuilder.install();

            assert resource instanceof KeyStoreResource;
            ((KeyStoreResource)resource).setKeyStoreServiceController(serviceController);

        }

        @Override
        protected Resource createResource(OperationContext context) {
            KeyStoreResource resource = new KeyStoreResource(Resource.Factory.create());
            context.addResource(PathAddress.EMPTY_ADDRESS, resource);

            return resource;
        }

    }

    private static ServiceName pathName(String relativeTo) {
        return ServiceName.JBOSS.append(ModelDescriptionConstants.SERVER, ModelDescriptionConstants.PATH, relativeTo);
    }

    private static String asStringIfDefined(OperationContext context, SimpleAttributeDefinition attributeDefintion, ModelNode model) throws OperationFailedException {
        ModelNode value = attributeDefintion.resolveModelAttribute(context, model);
        if (value.isDefined()) {
            return value.asString();
        }

        return null;
    }

    private static class KeyStoreRemoveHandler extends ServiceRemoveStepHandler {

        private KeyStoreRemoveHandler(final AbstractAddStepHandler add) {
            super(add);
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler() {
            super(ElytronDescriptionConstants.KEYSTORE, CONFIG_ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress arg0) {

            return null;
        }
    }

    /*
     * Runtime Attribute and Operation Handlers
     */

    abstract static class KeyStoreRuntimeOnlyHandler extends AbstractRuntimeOnlyHandler {

        private final boolean serviceMustBeUp;
        private final boolean writeAccess;

        KeyStoreRuntimeOnlyHandler(final boolean serviceMustBeUp, final boolean writeAccess) {
            this.serviceMustBeUp = serviceMustBeUp;
            this.writeAccess = writeAccess;
        }

        KeyStoreRuntimeOnlyHandler(final boolean serviceMustBeUp) {
            this(serviceMustBeUp, false);
        }


        @Override
        protected void executeRuntimeStep(OperationContext context, ModelNode operation) throws OperationFailedException {
            ServiceName keyStoreName = keyStoreServiceName(operation);
            @SuppressWarnings("unchecked")
            ServiceController<KeyStore> serviceContainer = (ServiceController<KeyStore>) context.getServiceRegistry(writeAccess).getRequiredService(keyStoreName);
            State serviceState;
            if ((serviceState = serviceContainer.getState()) != State.UP) {
                if (serviceMustBeUp) {
                    throw ROOT_LOGGER.requiredServiceNotUp(keyStoreName, serviceState);
                }
                return;
            }

            performRuntime(context.getResult(), operation, (KeyStoreService) serviceContainer.getService());
        }

        protected abstract void performRuntime(ModelNode result, ModelNode operation,  KeyStoreService keyStoreService) throws OperationFailedException;

    }

}
