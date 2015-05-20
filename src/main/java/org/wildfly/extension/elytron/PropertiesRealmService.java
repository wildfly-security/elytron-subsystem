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

import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.jboss.as.controller.services.path.PathEntry;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.as.controller.services.path.PathManager.Callback.Handle;
import org.jboss.as.controller.services.path.PathManager.Event;
import org.jboss.as.controller.services.path.PathManager.PathEventContext;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.auth.provider.LegacyPropertiesSecurityRealm;
import org.wildfly.security.auth.spi.SecurityRealm;

/**
 * A {@link Service} implementation responsible for supplying a {@link SecurityRealm} backed by a properties file.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class PropertiesRealmService implements Service<SecurityRealm> {

    private final String usersPath;
    private final String usersRelativeTo;
    private final String groupsPath;
    private final String groupsRelativeTo;
    private final boolean plainText;

    private final InjectedValue<PathManager> pathManager = new InjectedValue<PathManager>();
    private final List<Handle> callbackHandles = new ArrayList<>();
    private volatile SecurityRealm securityRealm;

    PropertiesRealmService(String usersPath, String usersRelativeTo, String groupsPath, String groupsRelativeTo, boolean plainText) {
        this.usersPath = usersPath;
        this.usersRelativeTo = usersRelativeTo;
        this.groupsPath = groupsPath;
        this.groupsRelativeTo = groupsRelativeTo;
        this.plainText = plainText;
    }

    @Override
    public void start(StartContext context) throws StartException {
        File usersFile = resolveFileLocation(usersPath, usersRelativeTo);
        File groupsFile = groupsPath != null ? resolveFileLocation(groupsPath, groupsRelativeTo) : null;

        try (InputStream usersInputStream = new FileInputStream(usersFile);
                InputStream groupsInputStream = groupsFile != null ? new FileInputStream(groupsFile) : null) {
            securityRealm = LegacyPropertiesSecurityRealm.builder()
                    .setPasswordsStream(usersInputStream)
                    .setGroupsStream(groupsInputStream)
                    .setPlainText(plainText)
                    .build();

        } catch (IOException e) {
            throw ROOT_LOGGER.unableToLoadPropertiesFiles(e);
        }
    }

    private File resolveFileLocation(String path, String relativeTo) {
        final File resolvedPath;
        if (relativeTo != null) {
            PathManager pathManager = this.pathManager.getValue();
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

    @Override
    public void stop(StopContext context) {
        securityRealm = null;
        Iterator<Handle> it = callbackHandles.iterator();
        while (it.hasNext()) {
            Handle handle = it.next();
            handle.remove();
            it.remove();
        }
    }

    Injector<PathManager> getPathManagerInjector() {
        return pathManager;
    }

    @Override
    public SecurityRealm getValue() throws IllegalStateException, IllegalArgumentException {
        return securityRealm;
    }

}
