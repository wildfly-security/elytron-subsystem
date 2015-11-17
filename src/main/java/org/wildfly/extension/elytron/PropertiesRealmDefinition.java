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
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.PATH;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.RELATIVE_TO;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.pathName;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.services.path.PathEntry;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.as.controller.services.path.PathManager.Callback.Handle;
import org.jboss.as.controller.services.path.PathManager.Event;
import org.jboss.as.controller.services.path.PathManager.PathEventContext;
import org.jboss.as.controller.services.path.PathManagerService;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.StartException;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.auth.provider.LegacyPropertiesSecurityRealm;
import org.wildfly.security.auth.server.SecurityRealm;

/**
 * A {@link ResourceDefinition} for a {@link SecurityRealm} backed by properties files.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class PropertiesRealmDefinition extends TrivialResourceDefinition<SecurityRealm> {

    static final ServiceUtil<SecurityRealm> REALM_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_REALM_RUNTIME_CAPABILITY, ElytronDescriptionConstants.PROPERTIES_REALM, SecurityRealm.class);

    static final ObjectTypeAttributeDefinition USERS_PROPERTIES = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.USERS_PROPERTIES, PATH, RELATIVE_TO)
        .setAllowNull(false)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final ObjectTypeAttributeDefinition GROUPS_PROPERTIES = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.GROUPS_PROPERTIES, PATH, RELATIVE_TO)
        .setAllowNull(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition PLAIN_TEXT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PLAIN_TEXT, ModelType.BOOLEAN, true)
        .setDefaultValue(new ModelNode(false))
        .setAllowExpression(true)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { USERS_PROPERTIES, GROUPS_PROPERTIES, PLAIN_TEXT };

    private static final AbstractAddStepHandler ADD = new TrivialAddHandler<SecurityRealm>(SECURITY_REALM_RUNTIME_CAPABILITY, SecurityRealm.class, ATTRIBUTES) {

        @Override
        protected ValueSupplier<SecurityRealm> getValueSupplier(ServiceBuilder<SecurityRealm> serviceBuilder,
                OperationContext context, ModelNode model) throws OperationFailedException {

            final String usersPath;
            final String usersRelativeTo;
            final String groupsPath;
            final String groupsRelativeTo;
            final boolean plainText = PLAIN_TEXT.resolveModelAttribute(context, model).asBoolean();

            ModelNode usersProperties = USERS_PROPERTIES.resolveModelAttribute(context, model);
            usersPath = asStringIfDefined(context, PATH, usersProperties);
            usersRelativeTo = asStringIfDefined(context, RELATIVE_TO, usersProperties);

            ModelNode groupsProperties = GROUPS_PROPERTIES.resolveModelAttribute(context, model);
            if (groupsProperties.isDefined()) {
                groupsPath = asStringIfDefined(context, PATH, groupsProperties);
                groupsRelativeTo = asStringIfDefined(context, RELATIVE_TO, groupsProperties);
            } else {
                groupsPath = null;
                groupsRelativeTo = null;
            }

            final InjectedValue<PathManager> pathManagerjector = new InjectedValue<PathManager>();

            if (usersRelativeTo != null || groupsRelativeTo != null) {
                serviceBuilder.addDependency(PathManagerService.SERVICE_NAME, PathManager.class, pathManagerjector);
                if (usersRelativeTo != null) {
                    serviceBuilder.addDependency(pathName(usersRelativeTo));
                }
                if (groupsRelativeTo != null) {
                    serviceBuilder.addDependency(pathName(groupsRelativeTo));
                }
            }

            return new ValueSupplier<SecurityRealm>() {

                private final List<Handle> callbackHandles = new ArrayList<>();

                @Override
                public SecurityRealm get() throws StartException {
                    File usersFile = resolveFileLocation(usersPath, usersRelativeTo);
                    File groupsFile = groupsPath != null ? resolveFileLocation(groupsPath, groupsRelativeTo) : null;

                    try (InputStream usersInputStream = new FileInputStream(usersFile);
                            InputStream groupsInputStream = groupsFile != null ? new FileInputStream(groupsFile) : null) {
                        return LegacyPropertiesSecurityRealm.builder()
                                .setPasswordsStream(usersInputStream)
                                .setGroupsStream(groupsInputStream)
                                .setPlainText(plainText)
                                .build();

                    } catch (IOException e) {
                        throw ROOT_LOGGER.unableToLoadPropertiesFiles(e);
                    }
                }

                @Override
                public void dispose() {
                    callbackHandles.forEach(h -> h.remove());
                }

                private File resolveFileLocation(String path, String relativeTo) {
                    final File resolvedPath;
                    if (relativeTo != null) {
                        PathManager pathManager =  pathManagerjector.getValue();
                        resolvedPath = new File(pathManager.resolveRelativePathEntry(path, relativeTo));
                        Handle callbackHandle = pathManager.registerCallback(relativeTo, new org.jboss.as.controller.services.path.PathManager.Callback() {

                            @Override
                            public void pathModelEvent(PathEventContext eventContext, String name) {
                                if (eventContext.isResourceServiceRestartAllowed() == false) {
                                    eventContext.reloadRequired();
                                }
                            }

                            @Override
                            public void pathEvent(Event event, PathEntry pathEntry) {
                                // Service dependencies should trigger a stop and start.
                            }
                        }, Event.REMOVED, Event.UPDATED);
                        callbackHandles.add(callbackHandle);
                    } else {
                        resolvedPath = new File(path);
                    }

                    return resolvedPath;
                }

            };
        }

    };

    PropertiesRealmDefinition() {
        super(ElytronDescriptionConstants.PROPERTIES_REALM, SECURITY_REALM_RUNTIME_CAPABILITY, SecurityRealm.class, ADD, ATTRIBUTES);
    }

}
