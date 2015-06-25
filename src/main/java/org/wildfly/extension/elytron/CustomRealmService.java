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

import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.resolveClassLoader;
import static org.wildfly.extension.elytron.SecurityActions.doPrivileged;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;

import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.wildfly.security.auth.spi.SecurityRealm;

/**
 * The {@link Service} implementation to manage the lifecycle of custom {@link SecurityRealm} instances.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class CustomRealmService implements Service<SecurityRealm> {

    private final String module;
    private final String slot;
    private final String className;
    private final Map<String, String> configuration;

    private SecurityRealm securityRealm;

    CustomRealmService(final String module, final String slot, final String className, final Map<String, String> configuration) {
        this.module = module;
        this.slot = slot;
        this.className = className;
        this.configuration = configuration;
    }

    @Override
    public void start(StartContext context) throws StartException {
        final ClassLoader classLoader;
        try {
            classLoader = doPrivileged((PrivilegedExceptionAction<ClassLoader>) () -> resolveClassLoader(module, slot));

            Class<? extends SecurityRealm> realmClazz = classLoader.loadClass(className).asSubclass(SecurityRealm.class);

            SecurityRealm securityRealm = realmClazz.newInstance();

            if (configuration != null) {
                if (securityRealm instanceof ConfigurableSecurityRealm == false) {
                    throw ROOT_LOGGER.realmNotConfigurable(className);
                }
                ConfigurableSecurityRealm configurableRealm = (ConfigurableSecurityRealm) securityRealm;
                configurableRealm.initialize(configuration);
            }

            this.securityRealm = securityRealm;
        } catch (PrivilegedActionException e) {
            throw new StartException(e.getCause());
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            throw new StartException(e);
        }
    }

    @Override
    public void stop(StopContext context) {
        securityRealm = null;
    }

    @Override
    public SecurityRealm getValue() throws IllegalStateException, IllegalArgumentException {
        return securityRealm;
    }

}
