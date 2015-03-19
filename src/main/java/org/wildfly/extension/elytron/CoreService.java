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

import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;

import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.wildfly.security.WildFlyElytronProvider;

/**
 * Core {@link Service} for the Elytron subsystem.
 *
 * Initially focused on provider registration but could cover further core initialisation requirements.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class CoreService implements Service<Void> {

    static final ServiceName SERVICE_NAME = ElytronExtension.BASE_SERVICE_NAME.append(ElytronDescriptionConstants.CORE_SERVICE);

    private volatile Provider provider;

    @Override
    public void start(StartContext context) throws StartException {
        provider = new WildFlyElytronProvider();
        SecurityActions.doPrivileged((PrivilegedAction<Void>) () -> {
            Security.addProvider(provider);
            return null;
        });
    }

    @Override
    public void stop(StopContext context) {
        SecurityActions.doPrivileged((PrivilegedAction<Void>) () -> {
            Security.removeProvider(provider.getName());
            return null;
        });
        provider = null;
    }

    @Override
    public Void getValue() throws IllegalStateException, IllegalArgumentException {
        return null;
    }

}
