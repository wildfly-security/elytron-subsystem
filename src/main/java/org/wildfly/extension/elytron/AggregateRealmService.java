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

import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.auth.provider.AggregateSecurityRealm;
import org.wildfly.security.auth.server.SecurityRealm;

/**
 * The {@link Service} to construct and return the {@link AggregateSecurityRealm} instance based on the two injected
 * {@link SecurityRealm} instances.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AggregateRealmService implements Service<SecurityRealm> {

    private volatile SecurityRealm securityRealm;

    private final InjectedValue<SecurityRealm> authenticationRealm = new InjectedValue<SecurityRealm>();
    private final InjectedValue<SecurityRealm> authorizationRealm = new InjectedValue<SecurityRealm>();

    @Override
    public void start(StartContext context) throws StartException {
        SecurityRealm authenticationRealm = this.authenticationRealm.getValue();
        SecurityRealm authorizationRealm = this.authorizationRealm.getValue();

        securityRealm = new AggregateSecurityRealm(authenticationRealm, authorizationRealm);
    }

    @Override
    public void stop(StopContext context) {
        this.securityRealm = null;
    }

    @Override
    public SecurityRealm getValue() throws IllegalStateException, IllegalArgumentException {
        return securityRealm;
    }

    Injector<SecurityRealm> getAuthenticationRealmInjector() {
        return authenticationRealm;
    }

    Injector<SecurityRealm> getAuthorizationRealmInjector() {
        return authenticationRealm;
    }
}
