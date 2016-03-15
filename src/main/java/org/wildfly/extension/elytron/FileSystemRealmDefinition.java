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

import static org.wildfly.extension.elytron.Capabilities.NAME_REWRITER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.pathName;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.pathResolver;

import java.nio.file.Path;
import java.security.KeyStore;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.as.controller.services.path.PathManagerService;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.jboss.msc.service.StartException;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.FileAttributeDefinitions.PathResolver;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.SecurityRealm;


/**
 * A {@link ResourceDefinition} for a {@link SecurityRealm} backed by a {@link KeyStore}.
 *
 * @author <a href="mailto:kabir.khan@jboss.com">Kabir Khan</a>
 */
class FileSystemRealmDefinition extends SimpleResourceDefinition {

    static final ServiceUtil<SecurityRealm> REALM_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_REALM_RUNTIME_CAPABILITY, ElytronDescriptionConstants.FILESYSTEM_REALM, SecurityRealm.class);

    static final SimpleAttributeDefinition PATH =
            new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PATH, FileAttributeDefinitions.PATH)
                    .setAttributeGroup(ElytronDescriptionConstants.FILE)
                    .setAllowNull(false)
                    .build();

    static final SimpleAttributeDefinition RELATIVE_TO =
            new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.RELATIVE_TO, FileAttributeDefinitions.RELATIVE_TO)
                    .setAttributeGroup(ElytronDescriptionConstants.FILE)
                    .build();

    static final SimpleAttributeDefinition LEVELS =
            new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.LEVELS, ModelType.INT, true)
                    .setDefaultValue(new ModelNode(2))
                    .build();

    static final SimpleAttributeDefinition NAME_REWRITER =
            new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.NAME_REWRITER, ModelType.STRING)
                    .setXmlName(ElytronDescriptionConstants.NAME)
                    .setCapabilityReference(NAME_REWRITER_CAPABILITY, SECURITY_REALM_CAPABILITY, true)
                    .setAllowNull(true)
                    .build();

    private static final AttributeDefinition[] ATTRIBUTES =
            new AttributeDefinition[]{PATH, RELATIVE_TO, LEVELS, NAME_REWRITER};

    private static final AbstractAddStepHandler ADD = new RealmAddHandler();
    private static final OperationStepHandler REMOVE = new SingleCapabilityServiceRemoveHandler<SecurityRealm>(ADD, SECURITY_REALM_RUNTIME_CAPABILITY, SecurityRealm.class);

    FileSystemRealmDefinition() {
        super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.FILESYSTEM_REALM),
                ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.FILESYSTEM_REALM))
            .setAddHandler(ADD)
            .setRemoveHandler(REMOVE)
            .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
            .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        OperationStepHandler handler = new WriteAttributeHandler();
        for (AttributeDefinition attr : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(attr, null, handler);
        }
    }

    @Override
    public void registerCapabilities(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerCapability(SECURITY_REALM_RUNTIME_CAPABILITY);
    }

    private static class RealmAddHandler extends BaseAddHandler {

        private RealmAddHandler() {
            super(SECURITY_REALM_RUNTIME_CAPABILITY, ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<Void> runtimeCapability = SECURITY_REALM_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName realmName = runtimeCapability.getCapabilityServiceName(SecurityRealm.class);
            String nameRewriter = asStringIfDefined(context, NAME_REWRITER, model);

            final int levels = LEVELS.resolveModelAttribute(context, model).asInt();

            final String path = PATH.resolveModelAttribute(context, model).asString();
            final String relativeTo = RELATIVE_TO.resolveModelAttribute(context, model).asString();

            final InjectedValue<PathManager> pathManagerInjector = new InjectedValue<>();
            final InjectedValue<NameRewriter> nameRewriterInjector = new InjectedValue<>();

            TrivialService<SecurityRealm> fileSystemRealmService = new TrivialService<>(
                    new TrivialService.ValueSupplier<SecurityRealm>() {

                        private PathResolver pathResolver;

                        @Override
                        public SecurityRealm get() throws StartException {
                            pathResolver = pathResolver();
                            Path rootPath = pathResolver.path(path).relativeTo(relativeTo, pathManagerInjector.getValue()).resolve().toPath();

                            NameRewriter nameRewriter = nameRewriterInjector.getOptionalValue();

                            return nameRewriter != null ?
                                    new FileSystemSecurityRealm(rootPath, nameRewriter, levels) :
                                    new FileSystemSecurityRealm(rootPath, levels);
                        }

                        @Override
                        public void dispose() {
                            if (pathResolver != null) {
                                pathResolver.clear();
                                pathResolver = null;
                            }
                        }

                    });

            ServiceBuilder<SecurityRealm> serviceBuilder = serviceTarget.addService(realmName, fileSystemRealmService);
            if (relativeTo != null) {
                serviceBuilder.addDependency(PathManagerService.SERVICE_NAME, PathManager.class, pathManagerInjector);
                serviceBuilder.addDependency(pathName(relativeTo));
            }
            if (nameRewriter != null) {
                String nameRewriteCapability = RuntimeCapability.buildDynamicCapabilityName(NAME_REWRITER_CAPABILITY, nameRewriter);
                ServiceName nameRewriterServiceName = context.getCapabilityServiceName(nameRewriteCapability, NameRewriter.class);
                serviceBuilder.addDependency(nameRewriterServiceName, NameRewriter.class, nameRewriterInjector);
            }
            serviceBuilder.install();
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler() {
            super(ElytronDescriptionConstants.FILESYSTEM_REALM, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress parentAddress) {
            final String name = parentAddress.getLastElement().getValue();
            return REALM_SERVICE_UTIL.serviceName(name);
        }
    }
}
