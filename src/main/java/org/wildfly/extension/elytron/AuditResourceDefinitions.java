/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import static org.wildfly.extension.elytron.Capabilities.SECURITY_EVENT_LISTENER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.FILE_AUDIT_LOG;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.RELATIVE_TO;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.pathName;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.pathResolver;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.io.File;
import java.io.IOException;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.as.controller.services.path.PathManagerService;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.FileAttributeDefinitions.PathResolver;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.extension.elytron.capabilities.SecurityEventListener;
import org.wildfly.security.audit.AuditEndpoint;
import org.wildfly.security.audit.AuditLogger;
import org.wildfly.security.audit.EventPriority;
import org.wildfly.security.audit.FileAuditEndpoint;
import org.wildfly.security.audit.JsonSecurityEventFormatter;
import org.wildfly.security.audit.SimpleSecurityEventFormatter;
import org.wildfly.security.auth.server.event.SecurityEventVisitor;

/**
 * Resources definitions for the audit logging resources.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class AuditResourceDefinitions {

    static final SimpleAttributeDefinition PATH = new SimpleAttributeDefinitionBuilder(FileAttributeDefinitions.PATH)
            .setRequired(true)
            .build();

    static final SimpleAttributeDefinition SYNCHRONIZED = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SYNCHRONIZED, ModelType.BOOLEAN, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(true))
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition FORMAT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.FORMAT, ModelType.STRING, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(Format.SIMPLE.toString()))
            .setAllowedValues(Format.SIMPLE.toString(), Format.JSON.toString())
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static ResourceDefinition getFileAuditLogResourceDefinition() {
        AttributeDefinition[] attributes = new AttributeDefinition[] {PATH, RELATIVE_TO, SYNCHRONIZED, FORMAT };
        AbstractAddStepHandler add = new TrivialAddHandler<SecurityEventListener>(SecurityEventListener.class, attributes, SECURITY_EVENT_LISTENER_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<SecurityEventListener> getValueSupplier(
                    ServiceBuilder<SecurityEventListener> serviceBuilder, OperationContext context, ModelNode model)
                    throws OperationFailedException {

                final boolean synv = SYNCHRONIZED.resolveModelAttribute(context, model).asBoolean();
                final Format format = Format.valueOf(FORMAT.resolveModelAttribute(context, model).asString());

                final InjectedValue<PathManager> pathManager = new InjectedValue<PathManager>();

                final String path = PATH.resolveModelAttribute(context, model).asString();
                final String relativeTo = asStringIfDefined(context, RELATIVE_TO, model);

                if (relativeTo != null) {
                    serviceBuilder.addDependency(PathManagerService.SERVICE_NAME, PathManager.class, pathManager);
                    serviceBuilder.addDependency(pathName(relativeTo));
                }

                return () -> {
                    PathResolver pathResolver = pathResolver();
                    pathResolver.path(path);
                    if (relativeTo != null) {
                        pathResolver.relativeTo(relativeTo, pathManager.getValue());
                    }
                    File resolvedPath = pathResolver.resolve();

                    final SecurityEventVisitor<?, String> formatter = Format.JSON == format ? JsonSecurityEventFormatter.builder().build() : SimpleSecurityEventFormatter.builder().build();
                    AuditEndpoint endpoint;
                    try {
                        endpoint = FileAuditEndpoint.builder().setLocation(resolvedPath.toPath()).setSyncOnAccept(synv).build();
                    } catch (IOException e) {
                        throw ROOT_LOGGER.unableToStartService(e);
                    }

                    return SecurityEventListener.from(AuditLogger.builder()
                            .setPriorityMapper(m -> EventPriority.WARNING)
                            .setMessageFormatter(m -> m.accept(formatter, null))
                            .setAuditEndpoint(endpoint)
                            .build());
                };
            }
        };

        return new TrivialResourceDefinition(FILE_AUDIT_LOG, add, attributes, SECURITY_EVENT_LISTENER_RUNTIME_CAPABILITY);
    }


    private enum Format {
        SIMPLE, JSON
    }

}
