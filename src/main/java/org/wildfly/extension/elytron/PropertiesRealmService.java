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

import org.jboss.as.controller.services.path.PathManager;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
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

    }

    @Override
    public void stop(StopContext context) {
        securityRealm = null;
    }

    Injector<PathManager> getPathManagerInjector() {
        return pathManager;
    }

    @Override
    public SecurityRealm getValue() throws IllegalStateException, IllegalArgumentException {
        return securityRealm;
    }

}
