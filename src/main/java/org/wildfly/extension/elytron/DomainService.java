/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.auth.login.SecurityDomain;
import org.wildfly.security.auth.spi.SecurityRealm;


/**
 * A {@link Service} responsible for managing the lifecycle of a single {@link SecurityDomain}.
 *
 * <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class DomainService implements Service<SecurityDomain> {

    private volatile SecurityDomain securityDomain;

    private final String name;
    private final String defaultRealm;
    private final Map<String, InjectedValue<SecurityRealm>> realms = new HashMap<>();

    DomainService(final String name, final String defaultRealm) {
        this.name = name;
        this.defaultRealm = defaultRealm;
    }

    Injector<SecurityRealm> createRealmInjector(final String realmName) throws OperationFailedException {
        if (realms.containsKey(realmName)) {
            throw ROOT_LOGGER.duplicateRealmInjection(name, realmName);
        }

        InjectedValue<SecurityRealm> injector = new InjectedValue<SecurityRealm>();
        realms.put(realmName, injector);
        return injector;
    }

    @Override
    public void start(StartContext context) throws StartException {
        SecurityDomain.Builder builder = SecurityDomain.builder();
        builder.setDefaultRealmName(defaultRealm);
        for (Entry<String, InjectedValue<SecurityRealm>> entry : realms.entrySet()) {
            builder.addRealm(entry.getKey(), entry.getValue().getValue());
        }

        securityDomain = builder.build();
    }

    @Override
    public void stop(StopContext context) {
       securityDomain = null;
    }

    @Override
    public SecurityDomain getValue() throws IllegalStateException, IllegalArgumentException {
        return securityDomain;
    }
}
