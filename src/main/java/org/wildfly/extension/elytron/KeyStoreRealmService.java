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

import java.security.KeyStore;

import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.auth.provider.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.provider.SecurityRealm;

/**
 * A {@link Service} implementation responsible for supplying a {@link SecurityRealm} backed by a referenced KeyStore.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class KeyStoreRealmService implements Service<SecurityRealm> {

    private final InjectedValue<KeyStore> keyStore = new InjectedValue<KeyStore>();

    private volatile SecurityRealm securityRealm;

    @Override
    public void start(StartContext context) throws StartException {
        securityRealm = new KeyStoreBackedSecurityRealm(keyStore.getValue());

    }

    @Override
    public void stop(StopContext context) {
        securityRealm = null;
    }

    @Override
    public SecurityRealm getValue() throws IllegalStateException, IllegalArgumentException {
        return securityRealm;
    }

    Injector<KeyStore> getKeyStoreInjector() {
        return keyStore;
    }

}
